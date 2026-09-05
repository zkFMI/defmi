//! AvalancheGo RPCChainVM protocol-45 implementation for QOMM.
//!
//! AvalancheGo owns consensus scheduling and the physical database. This
//! process owns canonical transaction parsing and the DeFMI state machine.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use avalanche_rpcchainvm_qomm::{
    app_sender::AppSender,
    database::{BatchOp, Database, DbError},
    http_bridge::{HttpBridge, HttpBridgeError},
    pb::{
        http::{
            http_server::Http, Element, HandleSimpleHttpRequest, HandleSimpleHttpResponse,
            HttpRequest, HttpResponse,
        },
        vm::{
            self as wire, state_summary_accept_response, vm_server::Vm, AppGossipMsg,
            AppRequestFailedMsg, AppRequestMsg, AppResponseMsg, BatchedParseBlockRequest,
            BatchedParseBlockResponse, BlockAcceptRequest, BlockRejectRequest, BlockVerifyRequest,
            BlockVerifyResponse, BuildBlockRequest, BuildBlockResponse, ConnectedRequest,
            CreateHandlersResponse, DisconnectedRequest, GatherResponse, GetAncestorsRequest,
            GetAncestorsResponse, GetBlockIdAtHeightRequest, GetBlockIdAtHeightResponse,
            GetBlockRequest, GetBlockResponse, GetLastStateSummaryResponse,
            GetOngoingSyncStateSummaryResponse, GetStateSummaryRequest, GetStateSummaryResponse,
            Handler, HealthResponse, InitializeRequest, InitializeResponse, NewHttpHandlerResponse,
            ParseBlockRequest, ParseBlockResponse, ParseStateSummaryRequest,
            ParseStateSummaryResponse, SetPreferenceRequest, SetStateRequest, SetStateResponse,
            StateSummaryAcceptRequest, StateSummaryAcceptResponse, StateSyncEnabledResponse,
            VersionResponse, WaitForEventResponse,
        },
    },
    plugin::{spawn_http_server, HttpServerHandle},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use prost_types::Timestamp;
use qomm_defmi::facility::QuorumAuthorizer;
use qomm_defmi::settlement_verifier::settlement_verifier_key;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{oneshot, Notify, RwLock};
use tonic::{Request, Response, Status};

use crate::{
    block::{Block, MAX_BLOCK_BYTES, MAX_TRANSACTIONS, MAX_TRANSACTION_BYTES},
    genesis::Genesis,
    id::Id,
    state::{id_key, State, TransitionReceipt},
    state_sync::{build_summary, decode_snapshot, ChunkRequest, ChunkResponse, StateSummary},
    transaction::TransactionEnvelope,
    VERSION,
};

const MAX_MEMPOOL_TRANSACTIONS: usize = 4_096;
const MAX_REJECTIONS: usize = 4_096;
const MAX_ANCESTORS: usize = 1_024;
const MAX_FUTURE_SKEW_SECONDS: i64 = 10;
const MAX_HTTP_BODY_BYTES: usize = MAX_TRANSACTION_BYTES + 64 * 1024;

const KEY_GENESIS_HASH: &[u8] = b"qomm/v1/meta/genesis-hash";
const KEY_GENESIS_BYTES: &[u8] = b"qomm/v1/meta/genesis-bytes";
const KEY_LAST_ACCEPTED: &[u8] = b"qomm/v1/meta/last-accepted";
const KEY_ONGOING_STATE_SYNC: &[u8] = b"qomm/v1/meta/ongoing-state-sync";
const KEY_LAST_COMPLETED_STATE_SYNC: &[u8] = b"qomm/v1/meta/last-completed-state-sync";
const PREFIX_BLOCK: &[u8] = b"qomm/v1/block/";
const PREFIX_STATE: &[u8] = b"qomm/v1/state/";
const PREFIX_HEIGHT: &[u8] = b"qomm/v1/height/";
const PREFIX_TRANSACTION: &[u8] = b"qomm/v1/transaction/";
const PREFIX_STATE_SYNC_CHUNK: &[u8] = b"qomm/v1/state-sync/chunk/";
const STATE_SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct QommVm {
    inner: Arc<RwLock<Option<Runtime>>>,
    events: Arc<Notify>,
    shutting_down: Arc<AtomicBool>,
}

impl Default for QommVm {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            events: Arc::new(Notify::new()),
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }
}

struct Runtime {
    db: Database,
    network_id: u32,
    subnet_id: Id,
    chain_id: Id,
    node_id: Vec<u8>,
    genesis: Genesis,
    genesis_bytes: Vec<u8>,
    authorizer: QuorumAuthorizer,
    engine_state: wire::State,
    last_accepted: VerifiedBlock,
    preferred: Id,
    verified: BTreeMap<Id, VerifiedBlock>,
    mempool: VecDeque<Vec<u8>>,
    pending: BTreeSet<Id>,
    processing: BTreeMap<Id, Vec<u8>>,
    rejected: BTreeMap<Id, String>,
    peers: BTreeSet<Vec<u8>>,
    engine_events: VecDeque<wire::Message>,
    ongoing_sync: Option<StateSummary>,
    last_completed_sync: Option<StateSummary>,
    sync_running: bool,
    last_sync_error: Option<String>,
    next_app_request_id: u32,
    pending_sync_requests: BTreeMap<u32, PendingSyncRequest>,
    app_sender: AppSender,
    api_server_address: Option<String>,
    fallback_server_address: Option<String>,
    http_servers: Vec<HttpServerHandle>,
}

struct PendingSyncRequest {
    peer: Vec<u8>,
    sender: oneshot::Sender<Result<Vec<u8>, String>>,
}

#[derive(Clone)]
struct VerifiedBlock {
    block: Block,
    bytes: Vec<u8>,
    id: Id,
    state: State,
    receipts: Vec<TransitionReceipt>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptedReceipt {
    transaction_id: [u8; 32],
    block_id: [u8; 32],
    height: u64,
    statement: [u8; 32],
    before_root: [u8; 32],
    after_root: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default = "empty_object")]
    params: Value,
}

fn empty_object() -> Value {
    json!({})
}

fn block_key(id: Id) -> Vec<u8> {
    prefixed(PREFIX_BLOCK, &id.0)
}

fn state_key(id: Id) -> Vec<u8> {
    prefixed(PREFIX_STATE, &id.0)
}

fn height_key(height: u64) -> Vec<u8> {
    prefixed(PREFIX_HEIGHT, &height.to_be_bytes())
}

fn transaction_key(id: Id) -> Vec<u8> {
    prefixed(PREFIX_TRANSACTION, &id.0)
}

fn state_sync_chunk_key(summary_id: Id, index: u32) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(36);
    suffix.extend_from_slice(&summary_id.0);
    suffix.extend_from_slice(&index.to_be_bytes());
    prefixed(PREFIX_STATE_SYNC_CHUNK, &suffix)
}

fn prefixed(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}

fn now_seconds() -> Result<i64, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes the Unix epoch".to_string())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "system clock exceeds the supported range".to_string())
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp { seconds, nanos: 0 }
}

fn deadline_expired(deadline: Option<&Timestamp>) -> Result<bool, String> {
    let Some(deadline) = deadline else {
        return Ok(false);
    };
    if deadline.seconds < 0 || !(0..1_000_000_000).contains(&deadline.nanos) {
        return Err("application request deadline is not a valid timestamp".into());
    }
    let deadline_seconds = u64::try_from(deadline.seconds)
        .map_err(|_| "application request deadline precedes the Unix epoch".to_string())?;
    let deadline_nanos = u32::try_from(deadline.nanos)
        .map_err(|_| "application request deadline nanoseconds are invalid".to_string())?;
    let deadline = UNIX_EPOCH
        .checked_add(Duration::new(deadline_seconds, deadline_nanos))
        .ok_or_else(|| "application request deadline exceeds the supported range".to_string())?;
    Ok(SystemTime::now() >= deadline)
}

fn invalid(message: impl Into<String>) -> Status {
    Status::invalid_argument(message.into())
}

fn failed(message: impl Into<String>) -> Status {
    Status::failed_precondition(message.into())
}

fn internal(message: impl Into<String>) -> Status {
    Status::internal(message.into())
}

fn db_error(error: DbError) -> Status {
    match error {
        DbError::NotFound => Status::not_found(error.to_string()),
        DbError::Closed => failed(error.to_string()),
        other => internal(other.to_string()),
    }
}

#[derive(Debug)]
struct ParseError(String);

impl From<String> for ParseError {
    fn from(error: String) -> Self {
        Self(error)
    }
}

impl From<ParseError> for Status {
    fn from(error: ParseError) -> Self {
        invalid(error.0)
    }
}

fn parse_id(bytes: &[u8], name: &str) -> Result<Id, ParseError> {
    Id::from_slice(bytes).map_err(|error| ParseError(format!("{name}: {error}")))
}

fn parse_text_id(value: &str, name: &str) -> Result<Id, String> {
    if let Ok(id) = Id::from_str(value) {
        return Ok(id);
    }
    let decoded = hex::decode(value).map_err(|_| format!("{name} is neither CB58 nor hex"))?;
    Id::from_slice(&decoded).map_err(|_| format!("{name} must contain 32 bytes"))
}

fn parse_block_bytes(bytes: Vec<u8>) -> Result<VerifiedBlock, ParseError> {
    let block = Block::decode(&bytes)?;
    let id = block.id()?;
    Ok(VerifiedBlock {
        block,
        bytes,
        id,
        state: State::default(),
        receipts: Vec::new(),
    })
}

fn parse_response(block: &VerifiedBlock) -> ParseBlockResponse {
    ParseBlockResponse {
        id: block.id.0.to_vec(),
        parent_id: block.block.parent_id.0.to_vec(),
        height: block.block.height,
        timestamp: Some(timestamp(block.block.timestamp)),
        verify_with_context: false,
    }
}

fn build_response(block: &VerifiedBlock) -> BuildBlockResponse {
    BuildBlockResponse {
        id: block.id.0.to_vec(),
        parent_id: block.block.parent_id.0.to_vec(),
        bytes: block.bytes.clone(),
        height: block.block.height,
        timestamp: Some(timestamp(block.block.timestamp)),
        verify_with_context: false,
    }
}

fn initialize_response(block: &VerifiedBlock) -> InitializeResponse {
    InitializeResponse {
        last_accepted_id: block.id.0.to_vec(),
        last_accepted_parent_id: block.block.parent_id.0.to_vec(),
        height: block.block.height,
        bytes: block.bytes.clone(),
        timestamp: Some(timestamp(block.block.timestamp)),
    }
}

fn set_state_response(block: &VerifiedBlock) -> SetStateResponse {
    SetStateResponse {
        last_accepted_id: block.id.0.to_vec(),
        last_accepted_parent_id: block.block.parent_id.0.to_vec(),
        height: block.block.height,
        bytes: block.bytes.clone(),
        timestamp: Some(timestamp(block.block.timestamp)),
    }
}

async fn optional_get(db: &Database, key: &[u8]) -> Result<Option<Vec<u8>>, Status> {
    match db.get(key).await {
        Ok(value) => Ok(Some(value)),
        Err(DbError::NotFound) => Ok(None),
        Err(error) => Err(db_error(error)),
    }
}

impl QommVm {
    async fn database(&self) -> Result<Database, Status> {
        self.inner
            .read()
            .await
            .as_ref()
            .map(|runtime| runtime.db.clone())
            .ok_or_else(|| failed("VM is not initialized"))
    }

    async fn load_block(&self, id: Id) -> Result<VerifiedBlock, Status> {
        let db = {
            let guard = self.inner.read().await;
            let runtime = guard
                .as_ref()
                .ok_or_else(|| failed("VM is not initialized"))?;
            if runtime.last_accepted.id == id {
                return Ok(runtime.last_accepted.clone());
            }
            if let Some(block) = runtime.verified.get(&id) {
                return Ok(block.clone());
            }
            runtime.db.clone()
        };
        let bytes = db.get(&block_key(id)).await.map_err(db_error)?;
        let parsed = parse_block_bytes(bytes)?;
        if parsed.id != id {
            return Err(internal("stored block ID does not match its key"));
        }
        let state =
            State::decode(&db.get(&state_key(id)).await.map_err(db_error)?).map_err(internal)?;
        Ok(VerifiedBlock { state, ..parsed })
    }

    async fn state_summary_for(
        &self,
        block: &VerifiedBlock,
    ) -> Result<(StateSummary, Vec<u8>), Status> {
        let (network_id, chain_id, genesis_hash) = {
            let guard = self.inner.read().await;
            let runtime = guard
                .as_ref()
                .ok_or_else(|| failed("VM is not initialized"))?;
            (
                runtime.network_id,
                runtime.chain_id,
                Id::digest(&runtime.genesis_bytes),
            )
        };
        build_summary(
            network_id,
            chain_id,
            genesis_hash,
            &block.block,
            &block.state,
        )
        .map_err(internal)
    }

    async fn validate_state_summary_chain(&self, summary: &StateSummary) -> Result<(), Status> {
        let guard = self.inner.read().await;
        let runtime = guard
            .as_ref()
            .ok_or_else(|| failed("VM is not initialized"))?;
        if !summary.matches_chain(
            runtime.network_id,
            runtime.chain_id,
            Id::digest(&runtime.genesis_bytes),
        ) {
            return Err(invalid("state summary belongs to another Avalanche chain"));
        }
        Ok(())
    }

    async fn local_state_snapshot(&self, summary: &StateSummary) -> Result<Vec<u8>, Status> {
        self.validate_state_summary_chain(summary).await?;
        let block = self.load_block(summary.block_id).await?;
        let (local, snapshot) = self.state_summary_for(&block).await?;
        if &local != summary {
            return Err(failed(
                "requested state summary does not match the local accepted snapshot",
            ));
        }
        Ok(snapshot)
    }

    async fn request_state_chunk(
        &self,
        peer: Vec<u8>,
        request: ChunkRequest,
    ) -> Result<Vec<u8>, String> {
        let body = request.encode()?;
        let (request_id, app_sender, receiver) = {
            let mut guard = self.inner.write().await;
            let runtime = guard
                .as_mut()
                .ok_or_else(|| "VM is not initialized".to_string())?;
            let mut selected = None;
            for _ in 0..=runtime.pending_sync_requests.len() {
                runtime.next_app_request_id = runtime.next_app_request_id.wrapping_add(1);
                if runtime.next_app_request_id != 0
                    && !runtime
                        .pending_sync_requests
                        .contains_key(&runtime.next_app_request_id)
                {
                    selected = Some(runtime.next_app_request_id);
                    break;
                }
            }
            let request_id = selected
                .ok_or_else(|| "no state-sync application request ID is available".to_string())?;
            let (sender, receiver) = oneshot::channel();
            runtime.pending_sync_requests.insert(
                request_id,
                PendingSyncRequest {
                    peer: peer.clone(),
                    sender,
                },
            );
            (request_id, runtime.app_sender.clone(), receiver)
        };
        if let Err(error) = app_sender.send_request(vec![peer], request_id, body).await {
            if let Some(runtime) = self.inner.write().await.as_mut() {
                runtime.pending_sync_requests.remove(&request_id);
            }
            return Err(error.to_string());
        }
        match tokio::time::timeout(STATE_SYNC_REQUEST_TIMEOUT, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("state-sync response channel closed".into()),
            Err(_) => {
                if let Some(runtime) = self.inner.write().await.as_mut() {
                    runtime.pending_sync_requests.remove(&request_id);
                }
                Err("state-sync chunk request timed out".into())
            }
        }
    }

    async fn install_state_summary(&self, summary: StateSummary) -> Result<(), String> {
        let (db, peers) = {
            let guard = self.inner.read().await;
            let runtime = guard
                .as_ref()
                .ok_or_else(|| "VM is not initialized".to_string())?;
            (
                runtime.db.clone(),
                runtime.peers.iter().cloned().collect::<Vec<_>>(),
            )
        };
        if peers.is_empty() {
            return Err("state sync has no connected Avalanche peers".into());
        }
        let summary_id = summary.id()?;
        let chunk_count = usize::try_from(summary.chunk_count)
            .map_err(|_| "state snapshot chunk count exceeds this platform".to_string())?;
        let mut chunks = Vec::with_capacity(chunk_count);
        for index in 0..summary.chunk_count {
            let key = state_sync_chunk_key(summary_id, index);
            let mut accepted = match db.get(&key).await {
                Ok(stored) => ChunkResponse::decode(&stored)
                    .and_then(|response| {
                        response.verify(&summary)?;
                        Ok(response.bytes)
                    })
                    .ok(),
                Err(DbError::NotFound) => None,
                Err(error) => return Err(error.to_string()),
            };
            if accepted.is_none() {
                let mut errors = Vec::new();
                for offset in 0..peers.len() {
                    let index_usize = usize::try_from(index)
                        .map_err(|_| "state chunk index exceeds this platform".to_string())?;
                    let peer = peers[(index_usize + offset) % peers.len()].clone();
                    match self
                        .request_state_chunk(
                            peer,
                            ChunkRequest {
                                summary: summary.clone(),
                                index,
                            },
                        )
                        .await
                        .and_then(|bytes| ChunkResponse::decode(&bytes))
                        .and_then(|response| {
                            response.verify(&summary)?;
                            Ok(response)
                        }) {
                        Ok(response) => {
                            db.put(&key, &response.encode()?)
                                .await
                                .map_err(|error| error.to_string())?;
                            accepted = Some(response.bytes);
                            break;
                        }
                        Err(error) => errors.push(error),
                    }
                }
                if accepted.is_none() {
                    return Err(format!(
                        "all state-sync peers failed chunk {index}: {}",
                        errors.join("; ")
                    ));
                }
            }
            chunks.push(
                accepted.ok_or_else(|| "state chunk was not accepted from any peer".to_string())?,
            );
        }
        let snapshot_len = usize::try_from(summary.snapshot_len)
            .map_err(|_| "state snapshot length exceeds this platform".to_string())?;
        let mut snapshot = Vec::with_capacity(snapshot_len);
        for chunk in chunks {
            snapshot.extend_from_slice(&chunk);
        }
        if snapshot.len() != snapshot_len {
            return Err("assembled state snapshot has the wrong length".into());
        }
        let decoded = decode_snapshot(&summary, &snapshot)?;
        let state_bytes = decoded.state.encode()?;
        let mut operations = vec![
            BatchOp::Put {
                key: KEY_LAST_ACCEPTED.to_vec(),
                value: summary.block_id.0.to_vec(),
            },
            BatchOp::Put {
                key: block_key(summary.block_id),
                value: decoded.block_bytes.clone(),
            },
            BatchOp::Put {
                key: state_key(summary.block_id),
                value: state_bytes,
            },
            BatchOp::Put {
                key: height_key(summary.height),
                value: summary.block_id.0.to_vec(),
            },
            BatchOp::Delete {
                key: KEY_ONGOING_STATE_SYNC.to_vec(),
            },
            BatchOp::Put {
                key: KEY_LAST_COMPLETED_STATE_SYNC.to_vec(),
                value: summary.encode()?,
            },
        ];
        for index in 0..summary.chunk_count {
            operations.push(BatchOp::Delete {
                key: state_sync_chunk_key(summary_id, index),
            });
        }
        {
            let guard = self.inner.read().await;
            let runtime = guard
                .as_ref()
                .ok_or_else(|| "VM is not initialized".to_string())?;
            if runtime.ongoing_sync.as_ref() != Some(&summary) || !runtime.sync_running {
                return Err("state-sync target changed before installation".into());
            }
        }
        db.write_batch(&operations)
            .await
            .map_err(|error| error.to_string())?;
        let accepted = VerifiedBlock {
            block: decoded.block,
            bytes: decoded.block_bytes,
            id: summary.block_id,
            state: decoded.state,
            receipts: Vec::new(),
        };
        let mut guard = self.inner.write().await;
        let runtime = guard
            .as_mut()
            .ok_or_else(|| "VM is not initialized".to_string())?;
        if runtime.ongoing_sync.as_ref() != Some(&summary) || !runtime.sync_running {
            return Err("state-sync target changed during installation".into());
        }
        runtime.last_accepted = accepted;
        runtime.preferred = summary.block_id;
        runtime.verified.clear();
        runtime.mempool.clear();
        runtime.pending.clear();
        runtime.processing.clear();
        runtime.rejected.clear();
        runtime.ongoing_sync = None;
        runtime.last_completed_sync = Some(summary);
        runtime.last_sync_error = None;
        Ok(())
    }

    async fn finish_state_sync(self, summary: StateSummary) {
        let result = self.install_state_summary(summary.clone()).await;
        let mut guard = self.inner.write().await;
        let Some(runtime) = guard.as_mut() else {
            return;
        };
        runtime.sync_running = false;
        if let Err(error) = result {
            runtime.last_sync_error = Some(error);
        }
        runtime
            .engine_events
            .push_back(wire::Message::StateSyncFinished);
        drop(guard);
        self.events.notify_one();
    }

    async fn verify_candidate(&self, bytes: Vec<u8>) -> Result<VerifiedBlock, Status> {
        let mut candidate = parse_block_bytes(bytes)?;
        if let Some(existing) = self
            .inner
            .read()
            .await
            .as_ref()
            .and_then(|runtime| runtime.verified.get(&candidate.id))
            .cloned()
        {
            return Ok(existing);
        }
        let parent = self.load_block(candidate.block.parent_id).await?;
        if candidate.block.height != parent.block.height.saturating_add(1) {
            return Err(invalid("block height does not follow its parent"));
        }
        if candidate.block.timestamp < parent.block.timestamp {
            return Err(invalid("block timestamp precedes its parent"));
        }
        if candidate.block.timestamp > now_seconds().map_err(internal)? + MAX_FUTURE_SKEW_SECONDS {
            return Err(invalid("block timestamp is too far in the future"));
        }
        let mut state = parent.state.clone();
        let authorizer = self
            .inner
            .read()
            .await
            .as_ref()
            .ok_or_else(|| failed("VM is not initialized"))?
            .authorizer
            .clone();
        let mut receipts = Vec::with_capacity(candidate.block.transactions.len());
        for transaction in &candidate.block.transactions {
            receipts.push(
                state
                    .apply(transaction, &authorizer, candidate.block.timestamp as u64)
                    .map_err(invalid)?,
            );
        }
        candidate.state = state;
        candidate.receipts = receipts;
        let mut guard = self.inner.write().await;
        let runtime = guard
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?;
        runtime.verified.insert(candidate.id, candidate.clone());
        Ok(candidate)
    }

    async fn enqueue(&self, bytes: Vec<u8>, gossip: bool) -> Result<Id, String> {
        if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
            return Err("transaction size is outside the allowed range".into());
        }
        let transaction = TransactionEnvelope::decode(&bytes)?;
        let id = transaction.id()?;
        let (db, sender) = {
            let guard = self.inner.read().await;
            let runtime = guard
                .as_ref()
                .ok_or_else(|| "VM is not initialized".to_string())?;
            (runtime.db.clone(), runtime.app_sender.clone())
        };
        if db
            .has(&transaction_key(id))
            .await
            .map_err(|error| error.to_string())?
        {
            return Ok(id);
        }
        {
            let mut guard = self.inner.write().await;
            let runtime = guard
                .as_mut()
                .ok_or_else(|| "VM is not initialized".to_string())?;
            if runtime.pending.contains(&id) || runtime.processing.contains_key(&id) {
                return Ok(id);
            }
            if runtime.mempool.len() >= MAX_MEMPOOL_TRANSACTIONS {
                return Err("DeFMI pending transaction pool is full".into());
            }
            runtime.rejected.remove(&id);
            runtime.pending.insert(id);
            runtime.mempool.push_back(bytes.clone());
        }
        self.events.notify_one();
        if gossip {
            if let Err(error) = sender.send_gossip(vec![], 64, 0, 0, bytes).await {
                eprintln!("qomm-avalanche-vm: transaction gossip deferred: {error}");
            }
        }
        Ok(id)
    }

    async fn get_or_spawn_http_server(&self, api: bool) -> Result<String, Status> {
        {
            let guard = self.inner.read().await;
            let runtime = guard
                .as_ref()
                .ok_or_else(|| failed("VM is not initialized"))?;
            let existing = if api {
                &runtime.api_server_address
            } else {
                &runtime.fallback_server_address
            };
            if let Some(address) = existing {
                return Ok(address.clone());
            }
        }
        let server = spawn_http_server(QommHttp {
            vm: self.clone(),
            api,
        })
        .await
        .map_err(|error| internal(error.to_string()))?;
        let address = server.address.to_string();
        let mut guard = self.inner.write().await;
        let runtime = guard
            .as_mut()
            .ok_or_else(|| failed("VM shut down while creating its HTTP handler"))?;
        let slot = if api {
            &mut runtime.api_server_address
        } else {
            &mut runtime.fallback_server_address
        };
        if let Some(existing) = slot {
            let existing = existing.clone();
            drop(guard);
            server
                .shutdown()
                .await
                .map_err(|error| internal(error.to_string()))?;
            return Ok(existing);
        }
        *slot = Some(address.clone());
        runtime.http_servers.push(server);
        Ok(address)
    }

    async fn json_rpc(&self, body: &[u8]) -> (i32, Vec<u8>) {
        let request = match serde_json::from_slice::<JsonRpcRequest>(body) {
            Ok(request) => request,
            Err(error) => {
                return rpc_error(Value::Null, -32700, format!("parse error: {error}"));
            }
        };
        let id = request.id.unwrap_or(Value::Null);
        if request.jsonrpc != "2.0"
            || request.method.is_empty()
            || request.method.len() > 96
            || !matches!(id, Value::Null | Value::String(_) | Value::Number(_))
            || !request.params.is_object()
        {
            return rpc_error(id, -32600, "invalid JSON-RPC request".into());
        }
        match self.rpc_result(&request.method, request.params).await {
            Ok(result) => (
                200,
                serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
                    .expect("JSON-RPC result is serializable"),
            ),
            Err(RpcFailure::MethodNotFound) => rpc_error(id, -32601, "method not found".into()),
            Err(RpcFailure::InvalidParams(message)) => rpc_error(id, -32602, message),
            Err(RpcFailure::Application(message)) => rpc_error(id, -32000, message),
        }
    }

    async fn rpc_result(&self, method: &str, params: Value) -> Result<Value, RpcFailure> {
        match method {
            "defmivm.network" => {
                let guard = self.inner.read().await;
                let runtime = guard
                    .as_ref()
                    .ok_or_else(|| RpcFailure::Application("VM is not initialized".into()))?;
                Ok(json!({
                    "networkID": runtime.network_id,
                    "subnetID": runtime.subnet_id.to_string(),
                    "chainID": runtime.chain_id.to_string(),
                }))
            }
            "defmivm.genesis" => {
                let guard = self.inner.read().await;
                let runtime = guard
                    .as_ref()
                    .ok_or_else(|| RpcFailure::Application("VM is not initialized".into()))?;
                Ok(json!({"genesis": {
                    "timestamp": runtime.genesis.timestamp,
                    "committee": {
                        "epoch": runtime.genesis.epoch,
                        "threshold": runtime.genesis.threshold,
                        "members": runtime.genesis.members.iter().map(|member| json!({
                            "nodeID": member.node_id,
                            "publicKey": hex::encode(member.public_key),
                        })).collect::<Vec<_>>()
                    }
                }}))
            }
            "defmivm.stateRoot" => {
                let guard = self.inner.read().await;
                let runtime = guard
                    .as_ref()
                    .ok_or_else(|| RpcFailure::Application("VM is not initialized".into()))?;
                Ok(json!({"stateRoot": hex::encode(runtime.last_accepted.state.root())}))
            }
            "defmivm.stateSyncStatus" => {
                let guard = self.inner.read().await;
                let runtime = guard
                    .as_ref()
                    .ok_or_else(|| RpcFailure::Application("VM is not initialized".into()))?;
                Ok(json!({
                    "enabled": true,
                    "running": runtime.sync_running,
                    "ongoingHeight": runtime.ongoing_sync.as_ref().map(|summary| summary.height),
                    "ongoingSummaryID": runtime.ongoing_sync.as_ref()
                        .and_then(|summary| summary.id().ok())
                        .map(|id| id.to_string()),
                    "lastCompletedHeight": runtime.last_completed_sync
                        .as_ref()
                        .map(|summary| summary.height),
                    "lastCompletedSummaryID": runtime.last_completed_sync.as_ref()
                        .and_then(|summary| summary.id().ok())
                        .map(|id| id.to_string()),
                    "pendingRequests": runtime.pending_sync_requests.len(),
                    "lastError": runtime.last_sync_error,
                }))
            }
            "defmivm.lastAccepted" => {
                let guard = self.inner.read().await;
                let runtime = guard
                    .as_ref()
                    .ok_or_else(|| RpcFailure::Application("VM is not initialized".into()))?;
                Ok(json!({
                    "blockID": runtime.last_accepted.id.to_string(),
                    "blockBytes": BASE64.encode(&runtime.last_accepted.bytes),
                }))
            }
            query
                if matches!(
                    query,
                    "defmivm.asset"
                        | "defmivm.guarantor"
                        | "defmivm.creditFacility"
                        | "defmivm.cSDIssuer"
                        | "defmivm.csdIssuer"
                        | "defmivm.creditHold"
                        | "defmivm.note"
                        | "defmivm.noteSerial"
                        | "defmivm.listNotes"
                        | "defmivm.noteReservation"
                        | "defmivm.applicationNoteReservation"
                        | "defmivm.applicationReserveScope"
                        | "defmivm.standingNotePool"
                        | "defmivm.noteClaim"
                        | "defmivm.listNoteClaims"
                        | "defmivm.settlementVerifier"
                        | "defmivm.admissionCursor"
                        | "defmivm.crossDomain"
                        | "defmivm.crossDomainLeg"
                        | "defmivm.crossDomainCommittee"
                        | "defmivm.bojLiquidity"
                        | "defmivm.bojParticipant"
                        | "defmivm.bojCollateral"
                        | "defmivm.bojReservation"
                        | "defmivm.participantRegistry"
                        | "defmivm.participant"
                        | "defmivm.mpcService"
                        | "defmivm.participantAccountBinding"
                        | "defmivm.participantServiceBinding"
                        | "defmivm.standingMandate"
                        | "defmivm.mandateReservation"
                ) =>
            {
                let guard = self.inner.read().await;
                let runtime = guard
                    .as_ref()
                    .ok_or_else(|| RpcFailure::Application("VM is not initialized".into()))?;
                canonical_state_snapshot(
                    &runtime.last_accepted.state,
                    query,
                    &params,
                    runtime.last_accepted.block.height,
                    u64::try_from(runtime.last_accepted.block.timestamp).map_err(|_| {
                        RpcFailure::Application("accepted block timestamp is negative".into())
                    })?,
                    runtime.last_accepted.id,
                )
            }
            "defmivm.previewStandingNotePoolAllocation" => {
                let guard = self.inner.read().await;
                let runtime = guard
                    .as_ref()
                    .ok_or_else(|| RpcFailure::Application("VM is not initialized".into()))?;
                let params = params.as_object().ok_or_else(|| {
                    RpcFailure::InvalidParams(
                        "standing-pool allocation preview params must be an object".into(),
                    )
                })?;
                let accepted_at =
                    u64::try_from(runtime.last_accepted.block.timestamp).map_err(|_| {
                        RpcFailure::Application("accepted block timestamp is negative".into())
                    })?;
                crate::execution::preview_standing_note_pool_allocation(
                    &runtime.last_accepted.state,
                    params,
                    &runtime.authorizer,
                    accepted_at,
                )
                .map_err(RpcFailure::Application)
            }
            "defmivm.txStatus" => self.transaction_status(&params).await,
            issue if issue.starts_with("defmivm.issue") => {
                let transaction =
                    TransactionEnvelope::new(issue, params).map_err(RpcFailure::InvalidParams)?;
                let id = self
                    .enqueue(
                        transaction.encode().map_err(RpcFailure::InvalidParams)?,
                        true,
                    )
                    .await
                    .map_err(RpcFailure::Application)?;
                Ok(json!({"txID": id.to_string()}))
            }
            _ => Err(RpcFailure::MethodNotFound),
        }
    }

    async fn transaction_status(&self, params: &Value) -> Result<Value, RpcFailure> {
        let value = params
            .get("txID")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcFailure::InvalidParams("txID must be a string".into()))?;
        let id = parse_text_id(value, "txID").map_err(RpcFailure::InvalidParams)?;
        let db = self
            .database()
            .await
            .map_err(|error| RpcFailure::Application(error.to_string()))?;
        if let Some(bytes) = optional_get(&db, &transaction_key(id))
            .await
            .map_err(|error| RpcFailure::Application(error.to_string()))?
        {
            let receipt: AcceptedReceipt = serde_json::from_slice(&bytes).map_err(|error| {
                RpcFailure::Application(format!("stored transition receipt is corrupt: {error}"))
            })?;
            return Ok(json!({
                "status": "accepted",
                "txID": id.to_string(),
                "blockID": Id(receipt.block_id).to_string(),
                "height": receipt.height,
                "statement": hex::encode(receipt.statement),
                "beforeRoot": hex::encode(receipt.before_root),
                "afterRoot": hex::encode(receipt.after_root),
            }));
        }
        let guard = self.inner.read().await;
        let runtime = guard
            .as_ref()
            .ok_or_else(|| RpcFailure::Application("VM is not initialized".into()))?;
        let (status, reason) = if runtime.pending.contains(&id) {
            ("pending", None)
        } else if runtime.processing.contains_key(&id) {
            ("processing", None)
        } else if let Some(reason) = runtime.rejected.get(&id) {
            ("rejected", Some(reason.clone()))
        } else {
            ("unknown", None)
        };
        let mut result = json!({"status": status, "txID": id.to_string()});
        if let Some(reason) = reason {
            result
                .as_object_mut()
                .expect("object")
                .insert("reason".into(), Value::String(reason));
        }
        Ok(result)
    }
}

fn canonical_state_snapshot(
    state: &State,
    method: &str,
    params: &Value,
    accepted_height: u64,
    accepted_at: u64,
    accepted_block_id: Id,
) -> Result<Value, RpcFailure> {
    let state_root = hex::encode(state.root());
    match method {
        "defmivm.asset" => {
            let (asset_id, key) = snapshot_id(params, "assetID")?;
            let record = state
                .assets
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("asset was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "assetID": hex::encode(asset_id),
                "code": record.code,
                "kind": record.kind,
                "decimals": record.decimals,
                "termsDigest": hex::encode(record.terms_digest),
                "active": record.active,
            }))
        }
        "defmivm.guarantor" => {
            let (guarantor_id, key) = snapshot_id(params, "guarantorID")?;
            let record = state
                .guarantors
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("guarantor was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "guarantorID": hex::encode(guarantor_id),
                "kind": record.kind,
                "name": record.name,
                "publicKey": hex::encode(record.public_key),
                "riskPolicyDigest": hex::encode(record.risk_policy_digest),
                "active": record.active,
            }))
        }
        "defmivm.creditFacility" => {
            let (facility_id, key) = snapshot_id(params, "facilityID")?;
            let record = state
                .credit_facilities
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("credit facility was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "facilityID": hex::encode(facility_id),
                "guarantorID": hex::encode(record.guarantor_id),
                "beneficiaryCommitment": hex::encode(record.beneficiary_commitment),
                "railAssetID": hex::encode(record.rail_asset_id),
                "capCommitment": hex::encode(record.cap_commitment),
                "availableCommitment": hex::encode(record.available_commitment),
                "heldCommitment": hex::encode(record.held_commitment),
                "outstandingCommitment": hex::encode(record.outstanding_commitment),
                "overlimitCommitment": hex::encode(record.overlimit_commitment),
                "collateralCommitment": hex::encode(record.collateral_commitment),
                "riskPolicyDigest": hex::encode(record.risk_policy_digest),
                "validFrom": record.valid_from,
                "validUntil": record.valid_until,
                "status": record.status,
                "sequence": record.sequence,
            }))
        }
        "defmivm.settlementVerifier" => {
            let venue_id = snapshot_hex32(params, "venueID")?;
            let epoch = snapshot_u64(params, "epoch")?;
            let key = id_key(&settlement_verifier_key(venue_id, epoch));
            let record = state.settlement_verifiers.get(&key).ok_or_else(|| {
                RpcFailure::Application("settlement verifier was not found".into())
            })?;
            Ok(json!({
                "stateRoot": state_root,
                "venueID": hex::encode(record.venue_id),
                "defmiID": hex::encode(record.defmi_id),
                "epoch": record.epoch,
                "quoteRegistryDigest": hex::encode(record.quote_registry_digest),
                "quoteEligibilityBits": record.quote_eligibility_bits,
                "quoteSpanBits": record.quote_span_bits,
                "amountBits": record.amount_bits,
                "priceBits": record.price_bits,
                "maxHorizon": record.max_horizon,
                "frostPublicPackage": BASE64.encode(&record.frost_public_package),
                "validFrom": record.valid_from,
                "validUntil": record.valid_until,
                "statement": hex::encode(record.statement),
            }))
        }
        "defmivm.admissionCursor" => {
            let venue_id = snapshot_hex32(params, "venueID")?;
            let epoch = snapshot_u64(params, "epoch")?;
            if epoch == 0 {
                return Err(RpcFailure::InvalidParams(
                    "admission cursor epoch must be greater than zero".into(),
                ));
            }
            let last_sequence = state
                .admission_entries
                .values()
                .filter(|entry| {
                    state
                        .admission_batches
                        .get(&id_key(&entry.batch_id))
                        .is_some_and(|batch| batch.venue_id == venue_id && batch.epoch == epoch)
                })
                .map(|entry| entry.sequence)
                .max()
                .unwrap_or(0);
            let next_sequence = last_sequence
                .checked_add(1)
                .ok_or_else(|| RpcFailure::Application("admission sequence is exhausted".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "venueID": hex::encode(venue_id),
                "epoch": epoch,
                "lastSequence": last_sequence,
                "nextSequence": next_sequence,
            }))
        }
        "defmivm.cSDIssuer" | "defmivm.csdIssuer" => {
            let (issuer_id, key) = snapshot_id(params, "issuerID")?;
            let record = state
                .csd_issuers
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("CSD issuer was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "issuerID": hex::encode(issuer_id),
                "code": record.code,
                "jurisdiction": record.jurisdiction,
                "operatorEntityCommitment": hex::encode(record.operator_entity_commitment),
                "publicKey": hex::encode(record.public_key),
                "permittedAssetIDs": record
                    .permitted_asset_ids
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
                "policyDigest": hex::encode(record.policy_digest),
                "validFrom": record.valid_from,
                "validUntil": record.valid_until,
                "status": record.status,
                "sequence": record.sequence,
            }))
        }
        "defmivm.creditHold" => {
            let (hold_id, key) = snapshot_id(params, "holdID")?;
            let record = state
                .credit_holds
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("credit hold was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "acceptedHeight": accepted_height,
                "holdID": hex::encode(hold_id),
                "facilityID": hex::encode(record.facility_id),
                "queryCommitment": hex::encode(record.query_commitment),
                "amountCommitment": hex::encode(record.amount_commitment),
                "expiresAt": record.expires_at,
                "status": record.status,
                "settlementDigest": hex::encode(record.settlement_digest),
                "createdSequence": record.created_sequence,
                "updatedSequence": record.updated_sequence,
            }))
        }
        "defmivm.note" => {
            let (note_id, key) = snapshot_id(params, "noteID")?;
            let record = state
                .notes
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("note was not found".into()))?;
            Ok(note_snapshot(&state_root, note_id, record))
        }
        "defmivm.noteSerial" => {
            let (serial_point, key) = snapshot_id(params, "serialPoint")?;
            Ok(json!({
                "stateRoot": state_root,
                "serialPoint": hex::encode(serial_point),
                "spent": state.note_serials.contains_key(&key),
            }))
        }
        "defmivm.listNotes" => note_page_snapshot(state, params, &state_root),
        "defmivm.applicationReserveScope" => {
            let (_, key) = snapshot_id(params, "scopeID")?;
            let scope = state.application_reserve_scopes.get(&key).ok_or_else(|| {
                RpcFailure::Application("application reserve scope was not found".into())
            })?;
            Ok(json!({"stateRoot": state_root, "acceptedHeight": accepted_height, "scope": scope}))
        }
        "defmivm.applicationNoteReservation" => {
            let (_, key) = snapshot_id(params, "holdID")?;
            let record = state.application_reservations.get(&key).ok_or_else(|| {
                RpcFailure::Application("application note reservation was not found".into())
            })?;
            Ok(json!({
                "stateRoot": state_root, "acceptedHeight": accepted_height,
                "binding": record.binding,
                "sequence": record.sequence,
                "remainingCommitment": hex::encode(record.remaining()),
                "headReceipt": hex::encode(record.head_receipt()),
                "remainingOpening": record.remaining_opening,
                "escrowNoteID": hex::encode(record.escrow_note_id),
                "proofDigest": hex::encode(record.proof_digest),
                "reserveReceiptDigest": hex::encode(record.receipt_digest),
                "status": record.status, "settlementDigest": hex::encode(record.settlement_digest),
            }))
        }
        "defmivm.noteReservation" => {
            let (hold_id, key) = snapshot_id(params, "holdID")?;
            let record = state
                .note_reservations
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("note reservation was not found".into()))?;
            let binding = state.reservation_bindings.get(&key).ok_or_else(|| {
                RpcFailure::Application("note reservation binding was not found".into())
            })?;
            Ok(json!({
                "stateRoot": state_root,
                "acceptedHeight": accepted_height,
                "holdID": hex::encode(hold_id),
                "escrowNoteID": hex::encode(record.escrow_note_id),
                "assetID": hex::encode(record.asset_id),
                "amountCommitment": hex::encode(record.amount_commitment),
                "proofDigest": hex::encode(record.proof_digest),
                "delegationDigest": hex::encode(record.delegation_digest),
                "reserveReceiptDigest": hex::encode(binding.receipt_digest),
                "status": record.status,
                "settlementDigest": hex::encode(record.settlement_digest),
            }))
        }
        "defmivm.standingNotePool" => {
            let (pool_id, key) = snapshot_id(params, "poolID")?;
            let record = state.standing_note_pools.get(&key).ok_or_else(|| {
                RpcFailure::Application("standing note pool was not found".into())
            })?;
            Ok(json!({
                "stateRoot": state_root,
                "poolID": hex::encode(pool_id),
                "venueID": hex::encode(record.venue_id),
                "defmiID": hex::encode(record.defmi_id),
                "entityCommitment": hex::encode(record.entity_commitment),
                "policyDigest": hex::encode(record.policy_digest),
                "mandateDigest": hex::encode(record.mandate_digest),
                "assetID": hex::encode(record.asset_id),
                "direction": record.direction,
                "maximumAmountCommitment": hex::encode(record.maximum_amount_commitment),
                "currentPoolNoteID": hex::encode(record.current_pool_note_id),
                "delegationDigest": hex::encode(record.delegation_digest),
                "committeeEpoch": record.committee_epoch,
                "validUntil": record.valid_until,
                "sequence": record.sequence,
                "status": record.status,
                "statement": hex::encode(record.statement),
            }))
        }
        "defmivm.noteClaim" => {
            let (claim_id, key) = snapshot_id(params, "claimID")?;
            let record = state
                .note_claims
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("note claim was not found".into()))?;
            Ok(note_claim_snapshot(&state_root, claim_id, record))
        }
        "defmivm.listNoteClaims" => note_claim_page_snapshot(state, params, &state_root),
        "defmivm.crossDomain" => {
            if params.as_object().is_none_or(|object| !object.is_empty()) {
                return Err(RpcFailure::InvalidParams(
                    "crossDomain takes an empty object".into(),
                ));
            }
            let domain = state.cross_domain_local_domain.as_ref().map(|domain| {
                json!({
                    "networkID": domain.network_id,
                    "chainID": hex::encode(domain.chain_id),
                    "defmiID": hex::encode(domain.defmi_id),
                    "domainID": hex::encode(domain.id()),
                })
            });
            let mut prepared = 0u64;
            let mut armed = 0u64;
            let mut claimed = 0u64;
            let mut refunded = 0u64;
            for record in state.cross_domain.legs.values() {
                match record.status {
                    qomm_defmi::cross_domain::LegStatus::Prepared => prepared += 1,
                    qomm_defmi::cross_domain::LegStatus::Armed => armed += 1,
                    qomm_defmi::cross_domain::LegStatus::Claimed => claimed += 1,
                    qomm_defmi::cross_domain::LegStatus::Refunded => refunded += 1,
                }
            }
            Ok(json!({
                "stateRoot": state_root,
                "localDomain": domain,
                "legCount": state.cross_domain.legs.len(),
                "consumedReceiptCount": state.cross_domain.consumed_receipts.len(),
                "committeeCount": state.cross_domain_committees.len(),
                "status": {
                    "prepared": prepared,
                    "armed": armed,
                    "claimed": claimed,
                    "refunded": refunded,
                }
            }))
        }
        "defmivm.crossDomainLeg" => {
            let (leg_id, _) = snapshot_id(params, "localLegID")?;
            let record =
                state.cross_domain.legs.get(&leg_id).ok_or_else(|| {
                    RpcFailure::Application("cross-domain leg was not found".into())
                })?;
            Ok(json!({
                "stateRoot": state_root,
                "acceptedHeight": accepted_height,
                "acceptedAt": accepted_at,
                "blockID": accepted_block_id.to_string(),
                "blockIDHex": hex::encode(accepted_block_id.0),
                "localLegID": hex::encode(leg_id),
                "localDomain": {
                    "networkID": record.prepare.local_domain.network_id,
                    "chainID": hex::encode(record.prepare.local_domain.chain_id),
                    "defmiID": hex::encode(record.prepare.local_domain.defmi_id),
                },
                "remoteDomain": {
                    "networkID": record.prepare.remote_domain.network_id,
                    "chainID": hex::encode(record.prepare.remote_domain.chain_id),
                    "defmiID": hex::encode(record.prepare.remote_domain.defmi_id),
                },
                "expectedRemotePrepareBinding": hex::encode(record.prepare.expected_remote_prepare_binding),
                "expectedRemoteClaimBinding": hex::encode(record.prepare.expected_remote_claim_binding),
                "ownerCommitment": hex::encode(record.prepare.owner_commitment),
                "escrowCommitment": hex::encode(record.prepare.escrow_commitment),
                "destinationCommitment": hex::encode(record.prepare.destination_commitment),
                "assetCommitment": hex::encode(record.prepare.asset_commitment),
                "amountCommitment": hex::encode(record.prepare.amount_commitment),
                "localInstructionDigest": hex::encode(record.prepare.local_instruction_digest),
                "localRelationProofDigest": hex::encode(record.prepare.local_relation_proof_digest),
                "reserveTransferDigest": hex::encode(record.prepare.reserve_transfer_digest),
                "claimTransferDigest": hex::encode(record.prepare.claim_transfer_digest),
                "refundTransferDigest": hex::encode(record.prepare.refund_transfer_digest),
                "armDeadline": record.prepare.arm_deadline,
                "claimDeadline": record.prepare.claim_deadline,
                "refundAfter": record.prepare.refund_after,
                "releaseCondition": hex::encode(record.prepare.release_condition),
                "status": match record.status {
                    qomm_defmi::cross_domain::LegStatus::Prepared => "prepared",
                    qomm_defmi::cross_domain::LegStatus::Armed => "armed",
                    qomm_defmi::cross_domain::LegStatus::Claimed => "claimed",
                    qomm_defmi::cross_domain::LegStatus::Refunded => "refunded",
                },
                "preparedAt": record.prepared_at,
                "armedAt": record.armed_at,
                "claimedAt": record.claimed_at,
                "refundedAt": record.refunded_at,
                "remotePrepareReceipt": record.remote_prepare_receipt.map(hex::encode),
                "remoteClaimReceipt": record.remote_claim_receipt.map(hex::encode),
            }))
        }
        "defmivm.crossDomainCommittee" => {
            let object = params.as_object().ok_or_else(|| {
                RpcFailure::InvalidParams("crossDomainCommittee params must be an object".into())
            })?;
            if object.len() != 2 {
                return Err(RpcFailure::InvalidParams(
                    "crossDomainCommittee needs domainID and epoch".into(),
                ));
            }
            let domain_id = object
                .get("domainID")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcFailure::InvalidParams("domainID must be hex".into()))?;
            let domain_id: [u8; 32] = hex::decode(domain_id)
                .map_err(|_| RpcFailure::InvalidParams("domainID must be hex".into()))?
                .try_into()
                .map_err(|_| RpcFailure::InvalidParams("domainID must be 32 bytes".into()))?;
            let epoch = object
                .get("epoch")
                .and_then(Value::as_u64)
                .ok_or_else(|| RpcFailure::InvalidParams("epoch must be an integer".into()))?;
            let key = crate::state::cross_domain_committee_key(&domain_id, epoch);
            let committee = state.cross_domain_committees.get(&key).ok_or_else(|| {
                RpcFailure::Application("cross-domain committee was not found".into())
            })?;
            Ok(json!({
                "stateRoot": state_root,
                "domain": {
                    "networkID": committee.domain.network_id,
                    "chainID": hex::encode(committee.domain.chain_id),
                    "defmiID": hex::encode(committee.domain.defmi_id),
                    "domainID": hex::encode(committee.domain.id()),
                },
                "epoch": committee.epoch,
                "quorumWeight": committee.quorum_weight,
                "members": committee.members.iter().map(|member| json!({
                    "memberID": hex::encode(member.member_id),
                    "publicKey": hex::encode(member.public_key),
                    "weight": member.weight,
                })).collect::<Vec<_>>(),
            }))
        }
        "defmivm.bojLiquidity" => {
            if params.as_object().is_none_or(|object| !object.is_empty()) {
                return Err(RpcFailure::InvalidParams(
                    "bojLiquidity takes an empty object".into(),
                ));
            }
            let mut active = 0u64;
            let mut shortfall = 0u64;
            let mut overdue = 0u64;
            let mut suspended = 0u64;
            for participant in state.boj_liquidity.participants.values() {
                match participant.status {
                    qomm_defmi::central_bank_liquidity::ParticipantStatus::Active => active += 1,
                    qomm_defmi::central_bank_liquidity::ParticipantStatus::CollateralShortfall => {
                        shortfall += 1
                    }
                    qomm_defmi::central_bank_liquidity::ParticipantStatus::Overdue => overdue += 1,
                    qomm_defmi::central_bank_liquidity::ParticipantStatus::Suspended => {
                        suspended += 1
                    }
                }
            }
            Ok(json!({
                "stateRoot": state_root,
                "acceptedHeight": accepted_height,
                "acceptedAt": accepted_at,
                "blockID": accepted_block_id.to_string(),
                "participantCount": state.boj_liquidity.participants.len(),
                "collateralLotCount": state.boj_liquidity.collateral_lots.len(),
                "reservationCount": state.boj_liquidity.reservations.len(),
                "settlementCount": state.boj_liquidity.completed_settlements.len(),
                "fundsReceiptCount": state.boj_liquidity.applied_funds_receipts.len(),
                "status": {
                    "active": active,
                    "collateralShortfall": shortfall,
                    "overdue": overdue,
                    "suspended": suspended,
                },
            }))
        }
        "defmivm.bojParticipant" => {
            let (entity_id, key) = snapshot_id(params, "legalEntityID")?;
            let participant =
                state.boj_liquidity.participants.get(&key).ok_or_else(|| {
                    RpcFailure::Application("BOJ participant was not found".into())
                })?;
            let collateral_value = state
                .boj_liquidity
                .collateral_value(&entity_id)
                .map_err(|error| RpcFailure::Application(error.to_string()))?;
            let live_reserved = state
                .boj_liquidity
                .live_reserved(&entity_id, accepted_at)
                .map_err(|error| RpcFailure::Application(error.to_string()))?;
            let available_headroom = state
                .boj_liquidity
                .available_headroom(&entity_id, accepted_at)
                .map_err(|error| RpcFailure::Application(error.to_string()))?;
            Ok(json!({
                "stateRoot": state_root,
                "acceptedHeight": accepted_height,
                "acceptedAt": accepted_at,
                "blockID": accepted_block_id.to_string(),
                "legalEntityID": hex::encode(entity_id),
                "fundsAccountID": hex::encode(participant.funds_account_id),
                "jgbAccountID": hex::encode(participant.jgb_account_id),
                "currentAccountBalanceYen": participant.current_account_balance_yen,
                "otherSecuredExposureYen": participant.other_secured_exposure_yen,
                "intradayOverdraftYen": participant.intraday_overdraft_yen,
                "liveReservedYen": live_reserved,
                "collateralValueYen": collateral_value,
                "availableHeadroomYen": available_headroom,
                "businessDay": participant.business_day,
                "repaymentDeadline": participant.repayment_deadline,
                "businessDayClosed": participant.business_day_closed,
                "sequence": participant.sequence,
                "status": match participant.status {
                    qomm_defmi::central_bank_liquidity::ParticipantStatus::Active => "active",
                    qomm_defmi::central_bank_liquidity::ParticipantStatus::CollateralShortfall => "collateral_shortfall",
                    qomm_defmi::central_bank_liquidity::ParticipantStatus::Overdue => "overdue",
                    qomm_defmi::central_bank_liquidity::ParticipantStatus::Suspended => "suspended",
                },
            }))
        }
        "defmivm.bojCollateral" => {
            let (lot_id, key) = snapshot_id(params, "lotID")?;
            let lot = state
                .boj_liquidity
                .collateral_lots
                .get(&key)
                .ok_or_else(|| {
                    RpcFailure::Application("JGB collateral lot was not found".into())
                })?;
            let collateral_value = lot
                .collateral_value_yen()
                .map_err(|error| RpcFailure::Application(error.to_string()))?;
            Ok(json!({
                "stateRoot": state_root,
                "acceptedHeight": accepted_height,
                "acceptedAt": accepted_at,
                "blockID": accepted_block_id.to_string(),
                "lotID": hex::encode(lot_id),
                "assetID": hex::encode(lot.asset_id),
                "ownerLegalEntityID": hex::encode(lot.owner_legal_entity_id),
                "faceValueYen": lot.face_value_yen,
                "marketPricePer100Micros": lot.market_price_per_100_micros,
                "indexRatioPpm": lot.index_ratio_ppm,
                "valuationRateBps": lot.valuation_rate_bps,
                "valuationEpoch": lot.valuation_epoch,
                "collateralValueYen": collateral_value,
                "pledged": lot.pledged,
                "sequence": lot.sequence,
            }))
        }
        "defmivm.participantRegistry" => {
            if params.as_object().is_none_or(|object| !object.is_empty()) {
                return Err(RpcFailure::InvalidParams(
                    "participantRegistry takes an empty object".into(),
                ));
            }
            let registry = &state.participant_registry;
            let mut active = 0u64;
            let mut suspended = 0u64;
            let mut revoked = 0u64;
            for participant in registry.participants.values() {
                match participant.status {
                    qomm_defmi::participant::ParticipantStatus::Active => active += 1,
                    qomm_defmi::participant::ParticipantStatus::Suspended => suspended += 1,
                    qomm_defmi::participant::ParticipantStatus::Revoked => revoked += 1,
                }
            }
            Ok(json!({
                "stateRoot": state_root,
                "acceptedHeight": accepted_height,
                "acceptedAt": accepted_at,
                "blockID": accepted_block_id.to_string(),
                "configuration": registry.configuration.as_ref().map(|configuration| json!({
                    "domainID": hex::encode(configuration.domain_id),
                    "templateDigest": hex::encode(configuration.template_digest),
                    "schemaDigest": hex::encode(configuration.schema_digest),
                    "templateVersion": configuration.template_version,
                })),
                "participantCount": registry.participants.len(),
                "accountBindingCount": registry.account_bindings.len(),
                "serviceCount": registry.services.len(),
                "serviceBindingCount": registry.service_bindings.len(),
                "mandateCount": registry.mandates.len(),
                "reservationCount": registry.reservations.len(),
                "status": {
                    "active": active,
                    "suspended": suspended,
                    "revoked": revoked,
                },
            }))
        }
        "defmivm.participant" => {
            let (participant_id, key) = snapshot_id(params, "participantID")?;
            let record = state
                .participant_registry
                .participants
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("participant was not found".into()))?;
            let purpose_key = |key: &qomm_defmi::participant::PurposeKey| {
                json!({
                    "publicKey": hex::encode(key.public_key),
                    "epoch": key.epoch,
                })
            };
            Ok(json!({
                "stateRoot": state_root,
                "participantID": hex::encode(participant_id),
                "legalEntityCredentialCommitment": hex::encode(record.legal_entity_credential_commitment),
                "credentialIssuerID": hex::encode(record.credential_issuer_id),
                "credentialSchemeDigest": hex::encode(record.credential_scheme_digest),
                "jurisdiction": record.jurisdiction,
                "roles": record.roles,
                "keys": {
                    "admin": purpose_key(&record.keys.admin),
                    "settlement": purpose_key(&record.keys.settlement),
                    "quote": purpose_key(&record.keys.quote),
                    "mpcInput": purpose_key(&record.keys.mpc_input),
                    "emergency": purpose_key(&record.keys.emergency),
                },
                "policyDigest": hex::encode(record.policy_digest),
                "validFrom": record.valid_from,
                "validUntil": record.valid_until,
                "sequence": record.sequence,
                "status": record.status,
            }))
        }
        "defmivm.mpcService" => {
            let (service_id, key) = snapshot_id(params, "serviceID")?;
            let service = state
                .participant_registry
                .services
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("MPC service was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "serviceID": hex::encode(service_id),
                "kind": service.kind,
                "programDigest": hex::encode(service.program_digest),
                "schemaDigest": hex::encode(service.schema_digest),
                "committeeEpoch": service.committee_epoch,
                "threshold": service.threshold,
                "members": service.members.iter().map(|member| json!({
                    "nodeID": hex::encode(member.node_id),
                    "operatorParticipantID": hex::encode(member.operator_participant_id),
                    "publicKey": hex::encode(member.public_key),
                })).collect::<Vec<_>>(),
                "validFrom": service.valid_from,
                "validUntil": service.valid_until,
                "sequence": service.sequence,
                "status": service.status,
            }))
        }
        "defmivm.participantAccountBinding" => {
            let (binding_id, key) = snapshot_id(params, "bindingID")?;
            let binding = state
                .participant_registry
                .account_bindings
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("account binding was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "bindingID": hex::encode(binding_id),
                "participantID": hex::encode(binding.participant_id),
                "accountCommitment": hex::encode(binding.account_commitment),
                "assetID": hex::encode(binding.asset_id),
                "kind": binding.kind,
                "controlProofDigest": hex::encode(binding.control_proof_digest),
                "validFrom": binding.valid_from,
                "validUntil": binding.valid_until,
                "sequence": binding.sequence,
                "active": binding.active,
            }))
        }
        "defmivm.participantServiceBinding" => {
            let (binding_id, key) = snapshot_id(params, "bindingID")?;
            let binding = state
                .participant_registry
                .service_bindings
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("service binding was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "bindingID": hex::encode(binding_id),
                "participantID": hex::encode(binding.participant_id),
                "serviceID": hex::encode(binding.service_id),
                "serviceEpoch": binding.service_epoch,
                "inputPublicKey": hex::encode(binding.input_public_key),
                "capabilityDigest": hex::encode(binding.capability_digest),
                "validFrom": binding.valid_from,
                "validUntil": binding.valid_until,
                "sequence": binding.sequence,
                "active": binding.active,
            }))
        }
        "defmivm.standingMandate" => {
            let (mandate_id, key) = snapshot_id(params, "mandateID")?;
            let mandate = state
                .participant_registry
                .mandates
                .get(&key)
                .ok_or_else(|| RpcFailure::Application("standing mandate was not found".into()))?;
            Ok(json!({
                "stateRoot": state_root,
                "mandateID": hex::encode(mandate_id),
                "participantID": hex::encode(mandate.participant_id),
                "serviceID": hex::encode(mandate.service_id),
                "serviceBindingID": hex::encode(mandate.service_binding_id),
                "role": mandate.role,
                "accountBindingIDs": mandate.account_binding_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                "permittedAssetIDs": mandate.permitted_asset_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                "permittedDestinationDomains": mandate.permitted_destination_domains.iter().map(hex::encode).collect::<Vec<_>>(),
                "limitCommitment": hex::encode(mandate.limit_commitment),
                "limitPolicyDigest": hex::encode(mandate.limit_policy_digest),
                "settlementPolicyDigest": hex::encode(mandate.settlement_policy_digest),
                "maxActiveReservations": mandate.max_active_reservations,
                "activeReservations": mandate.active_reservations,
                "validFrom": mandate.valid_from,
                "validUntil": mandate.valid_until,
                "sequence": mandate.sequence,
                "automaticSettlement": mandate.automatic_settlement,
                "status": mandate.status,
            }))
        }
        "defmivm.mandateReservation" => {
            let (reservation_id, key) = snapshot_id(params, "reservationID")?;
            let reservation = state
                .participant_registry
                .reservations
                .get(&key)
                .ok_or_else(|| {
                    RpcFailure::Application("mandate reservation was not found".into())
                })?;
            Ok(json!({
                "stateRoot": state_root,
                "reservationID": hex::encode(reservation_id),
                "mandateID": hex::encode(reservation.mandate_id),
                "serviceID": hex::encode(reservation.service_id),
                "serviceEpoch": reservation.service_epoch,
                "accountBindingID": hex::encode(reservation.account_binding_id),
                "assetID": hex::encode(reservation.asset_id),
                "amountCommitment": hex::encode(reservation.amount_commitment),
                "underlyingReservationDigest": hex::encode(reservation.underlying_reservation_digest),
                "admissionReceiptDigest": hex::encode(reservation.admission_receipt_digest),
                "limitProofDigest": hex::encode(reservation.limit_proof_digest),
                "zkpiDigest": hex::encode(reservation.zkpi_digest),
                "expiresAt": reservation.expires_at,
                "status": reservation.status,
                "settlementDigest": hex::encode(reservation.settlement_digest),
            }))
        }
        "defmivm.bojReservation" => {
            let (reservation_id, key) = snapshot_id(params, "reservationID")?;
            let reservation = state.boj_liquidity.reservations.get(&key).ok_or_else(|| {
                RpcFailure::Application("intraday reservation was not found".into())
            })?;
            Ok(json!({
                "stateRoot": state_root,
                "acceptedHeight": accepted_height,
                "acceptedAt": accepted_at,
                "blockID": accepted_block_id.to_string(),
                "reservationID": hex::encode(reservation_id),
                "legalEntityID": hex::encode(reservation.legal_entity_id),
                "instructionCommitment": hex::encode(reservation.instruction_commitment),
                "amountYen": reservation.amount_yen,
                "expiresAt": reservation.expires_at,
                "live": reservation.status == qomm_defmi::central_bank_liquidity::ReservationStatus::Active
                    && accepted_at < reservation.expires_at,
                "status": match reservation.status {
                    qomm_defmi::central_bank_liquidity::ReservationStatus::Active => "active",
                    qomm_defmi::central_bank_liquidity::ReservationStatus::Consumed => "consumed",
                    qomm_defmi::central_bank_liquidity::ReservationStatus::Released => "released",
                },
                "consumedYen": reservation.consumed_yen,
            }))
        }
        _ => Err(RpcFailure::MethodNotFound),
    }
}

fn snapshot_id(params: &Value, name: &str) -> Result<([u8; 32], String), RpcFailure> {
    let raw = params
        .as_object()
        .and_then(|object| object.get(name))
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFailure::InvalidParams(format!("{name} must be a hexadecimal string")))?;
    let value: [u8; 32] = hex::decode(raw)
        .map_err(|_| RpcFailure::InvalidParams(format!("{name} is not hexadecimal")))?
        .try_into()
        .map_err(|_| RpcFailure::InvalidParams(format!("{name} must contain 32 bytes")))?;
    Ok((value, hex::encode(value)))
}

fn snapshot_hex32(params: &Value, name: &str) -> Result<[u8; 32], RpcFailure> {
    snapshot_id(params, name).map(|(value, _)| value)
}

fn snapshot_u64(params: &Value, name: &str) -> Result<u64, RpcFailure> {
    params
        .as_object()
        .and_then(|object| object.get(name))
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcFailure::InvalidParams(format!("{name} must be an unsigned integer")))
}

fn note_snapshot(state_root: &str, note_id: [u8; 32], record: &crate::state::NoteRecord) -> Value {
    json!({
        "stateRoot": state_root,
        "noteID": hex::encode(note_id),
        "assetID": hex::encode(record.asset_id),
        "oneTime": hex::encode(record.one_time),
        "valueCommitment": hex::encode(record.value_commitment),
        "ephemeral": hex::encode(record.ephemeral),
        "maskedValue": hex::encode(record.masked_value),
        "maskedBlinding": hex::encode(record.masked_blinding),
        "lockID": hex::encode(record.lock_id),
    })
}

fn note_page_snapshot(
    state: &State,
    params: &Value,
    state_root: &str,
) -> Result<Value, RpcFailure> {
    let (asset_id, _) = snapshot_id(params, "assetID")?;
    let object = params
        .as_object()
        .ok_or_else(|| RpcFailure::InvalidParams("params must be an object".into()))?;
    let after = match object.get("after").and_then(Value::as_str) {
        None | Some("") => None,
        Some(_) => Some(snapshot_id(params, "after")?.0),
    };
    let limit = match object.get("limit") {
        None => 64_usize,
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| (1..=256).contains(value))
            .ok_or_else(|| {
                RpcFailure::InvalidParams("limit must be an integer between 1 and 256".into())
            })?,
    };
    let mut page = Vec::with_capacity(limit);
    let mut last = None;
    for (key, record) in &state.notes {
        if record.asset_id != asset_id {
            continue;
        }
        let note_id: [u8; 32] = hex::decode(key)
            .expect("validated canonical note key")
            .try_into()
            .expect("validated 32-byte note key");
        if after.is_some_and(|cursor| note_id <= cursor) {
            continue;
        }
        page.push(note_snapshot(state_root, note_id, record));
        last = Some(note_id);
        if page.len() == limit {
            break;
        }
    }
    Ok(json!({
        "stateRoot": state_root,
        "notes": page,
        "next": last.filter(|_| page.len() == limit).map(hex::encode).unwrap_or_default(),
    }))
}

fn note_claim_snapshot(
    state_root: &str,
    claim_id: [u8; 32],
    record: &crate::state::NoteClaimRecord,
) -> Value {
    json!({
        "stateRoot": state_root,
        "claimID": hex::encode(claim_id),
        "assetID": hex::encode(record.asset_id),
        "valueCommitment": hex::encode(record.value_commitment),
        "recipientCommitment": hex::encode(record.recipient_commitment),
        "sourceHoldID": hex::encode(record.source_hold_id),
        "kind": record.kind,
        "status": record.status,
        "settlementDigest": hex::encode(record.settlement_digest),
        "materialization": hex::encode(record.materialization),
        "openingEnvelope": {
            "context": hex::encode(record.opening_envelope.context),
            "threshold": record.opening_envelope.threshold,
            "recipientView": hex::encode(record.opening_envelope.recipient_view),
            "shares": record.opening_envelope.shares.iter().map(|share| json!({
                "party": share.party,
                "ephemeral": hex::encode(share.ephemeral),
                "maskedValue": hex::encode(share.masked_value),
                "maskedBlinding": hex::encode(share.masked_blinding),
            })).collect::<Vec<_>>(),
        },
    })
}

fn note_claim_page_snapshot(
    state: &State,
    params: &Value,
    state_root: &str,
) -> Result<Value, RpcFailure> {
    let object = params
        .as_object()
        .ok_or_else(|| RpcFailure::InvalidParams("params must be an object".into()))?;
    let source_hold_id = object
        .get("sourceHoldID")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|_| snapshot_id(params, "sourceHoldID").map(|value| value.0))
        .transpose()?;
    let recipient_view = object
        .get("recipientView")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|_| snapshot_id(params, "recipientView").map(|value| value.0))
        .transpose()?;
    if source_hold_id.is_some() == recipient_view.is_some() {
        return Err(RpcFailure::InvalidParams(
            "exactly one of sourceHoldID or recipientView is required".into(),
        ));
    }
    let after = match object.get("after").and_then(Value::as_str) {
        None | Some("") => None,
        Some(_) => Some(snapshot_id(params, "after")?.0),
    };
    let limit = match object.get("limit") {
        None => 64_usize,
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| (1..=256).contains(value))
            .ok_or_else(|| {
                RpcFailure::InvalidParams("limit must be an integer between 1 and 256".into())
            })?,
    };
    let mut page = Vec::with_capacity(limit);
    let mut last = None;
    for (key, record) in &state.note_claims {
        if source_hold_id.is_some_and(|source| record.source_hold_id != source)
            || recipient_view
                .is_some_and(|recipient| record.opening_envelope.recipient_view != recipient)
        {
            continue;
        }
        let claim_id: [u8; 32] = hex::decode(key)
            .expect("validated canonical note-claim key")
            .try_into()
            .expect("validated 32-byte note-claim key");
        if after.is_some_and(|cursor| claim_id <= cursor) {
            continue;
        }
        page.push(note_claim_snapshot(state_root, claim_id, record));
        last = Some(claim_id);
        if page.len() == limit {
            break;
        }
    }
    Ok(json!({
        "stateRoot": state_root,
        "claims": page,
        "next": last.filter(|_| page.len() == limit).map(hex::encode).unwrap_or_default(),
    }))
}

enum RpcFailure {
    MethodNotFound,
    InvalidParams(String),
    Application(String),
}

fn rpc_error(id: Value, code: i64, message: String) -> (i32, Vec<u8>) {
    (
        200,
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": code, "message": message},
        }))
        .expect("JSON-RPC error is serializable"),
    )
}

#[derive(Clone)]
struct QommHttp {
    vm: QommVm,
    api: bool,
}

impl QommHttp {
    fn json_content_type() -> Element {
        Element {
            key: "Content-Type".into(),
            values: vec!["application/json".into()],
        }
    }

    fn body_too_large() -> HandleSimpleHttpResponse {
        HandleSimpleHttpResponse {
            code: 413,
            headers: vec![Self::json_content_type()],
            body: br#"{"error":"request body exceeds DeFMI RPC limit"}"#.to_vec(),
        }
    }

    async fn dispatch(&self, method: &str, body: &[u8]) -> HandleSimpleHttpResponse {
        let content_type = Self::json_content_type();
        if !self.api {
            return HandleSimpleHttpResponse {
                code: 404,
                headers: vec![content_type],
                body: br#"{"error":"not found"}"#.to_vec(),
            };
        }
        if method != "POST" {
            return HandleSimpleHttpResponse {
                code: 405,
                headers: vec![content_type],
                body: br#"{"error":"method not allowed"}"#.to_vec(),
            };
        }
        if body.is_empty() || body.len() > MAX_HTTP_BODY_BYTES {
            return Self::body_too_large();
        }
        let (code, body) = self.vm.json_rpc(body).await;
        HandleSimpleHttpResponse {
            code,
            headers: vec![content_type],
            body,
        }
    }
}

#[tonic::async_trait]
impl Http for QommHttp {
    async fn handle(
        &self,
        request: Request<HttpRequest>,
    ) -> Result<Response<HttpResponse>, Status> {
        let request = request.into_inner();
        let writer = request
            .response_writer
            .ok_or_else(|| invalid("Avalanche HTTP request omitted its response writer"))?;
        let request = request
            .request
            .ok_or_else(|| invalid("Avalanche HTTP request omitted its request metadata"))?;
        if writer.server_addr.is_empty() {
            return Err(invalid("Avalanche HTTP response-writer address is empty"));
        }
        let mut bridge = HttpBridge::connect(&writer.server_addr, MAX_HTTP_BODY_BYTES)
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        let upgrade = request.header.iter().any(|header| {
            header.key.eq_ignore_ascii_case("upgrade")
                && header.values.iter().any(|value| !value.is_empty())
        });
        let response = if upgrade {
            HandleSimpleHttpResponse {
                code: 426,
                headers: vec![Self::json_content_type()],
                body: br#"{"error":"QOMM JSON-RPC does not support protocol upgrades"}"#.to_vec(),
            }
        } else if request.content_length > MAX_HTTP_BODY_BYTES as i64 {
            Self::body_too_large()
        } else {
            match bridge.read_body().await {
                Ok(body) => self.dispatch(&request.method, &body).await,
                Err(HttpBridgeError::BodyTooLarge { .. }) => Self::body_too_large(),
                Err(error) => return Err(Status::internal(error.to_string())),
            }
        };
        bridge
            .write_response(response.code, &response.headers, &response.body)
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(Response::new(HttpResponse {
            header: response.headers,
        }))
    }

    async fn handle_simple(
        &self,
        request: Request<HandleSimpleHttpRequest>,
    ) -> Result<Response<HandleSimpleHttpResponse>, Status> {
        let request = request.into_inner();
        Ok(Response::new(
            self.dispatch(&request.method, &request.body).await,
        ))
    }
}

#[tonic::async_trait]
impl Vm for QommVm {
    async fn initialize(
        &self,
        request: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>, Status> {
        if self.inner.read().await.is_some() {
            return Err(failed("VM is already initialized"));
        }
        let request = request.into_inner();
        let subnet_id = parse_id(&request.subnet_id, "subnet ID")?;
        let chain_id = parse_id(&request.chain_id, "chain ID")?;
        if request.node_id.len() != 20 {
            return Err(invalid("Avalanche node ID must contain 20 bytes"));
        }
        for (name, value) in [
            ("X-chain ID", &request.x_chain_id),
            ("C-chain ID", &request.c_chain_id),
            ("AVAX asset ID", &request.avax_asset_id),
        ] {
            parse_id(value, name)?;
        }
        if !request.upgrade_bytes.is_empty() {
            return Err(invalid(
                "QOMM VM upgrade bytes are not supported by this version",
            ));
        }
        if !request.config_bytes.is_empty() {
            let config: Value = serde_json::from_slice(&request.config_bytes)
                .map_err(|error| invalid(format!("VM config is invalid JSON: {error}")))?;
            if config != json!({}) {
                return Err(invalid(
                    "this QOMM VM version accepts only an empty config object",
                ));
            }
        }
        let genesis = Genesis::decode(&request.genesis_bytes).map_err(invalid)?;
        let authorizer = genesis.authorizer(&chain_id.to_string()).map_err(invalid)?;
        let genesis_hash = Id::digest(&request.genesis_bytes);
        let db = Database::connect(&request.db_server_addr)
            .await
            .map_err(db_error)?;
        let app_sender = AppSender::connect(&request.server_addr)
            .await
            .map_err(|error| internal(error.to_string()))?;

        let last_accepted = match optional_get(&db, KEY_GENESIS_HASH).await? {
            None => {
                let block = Block {
                    parent_id: genesis_hash,
                    timestamp: genesis.timestamp,
                    height: 0,
                    transactions: Vec::new(),
                };
                let bytes = block.encode().map_err(internal)?;
                let id = block.id().map_err(internal)?;
                let state = State::default();
                db.write_batch(&[
                    BatchOp::Put {
                        key: KEY_GENESIS_HASH.to_vec(),
                        value: genesis_hash.0.to_vec(),
                    },
                    BatchOp::Put {
                        key: KEY_GENESIS_BYTES.to_vec(),
                        value: request.genesis_bytes.clone(),
                    },
                    BatchOp::Put {
                        key: KEY_LAST_ACCEPTED.to_vec(),
                        value: id.0.to_vec(),
                    },
                    BatchOp::Put {
                        key: block_key(id),
                        value: bytes.clone(),
                    },
                    BatchOp::Put {
                        key: state_key(id),
                        value: state.encode().map_err(internal)?,
                    },
                    BatchOp::Put {
                        key: height_key(0),
                        value: id.0.to_vec(),
                    },
                ])
                .await
                .map_err(db_error)?;
                VerifiedBlock {
                    block,
                    bytes,
                    id,
                    state,
                    receipts: Vec::new(),
                }
            }
            Some(stored_hash) => {
                if stored_hash != genesis_hash.0
                    || optional_get(&db, KEY_GENESIS_BYTES).await?.as_deref()
                        != Some(request.genesis_bytes.as_slice())
                {
                    return Err(failed("genesis differs from the initialized chain"));
                }
                let last_id = parse_id(
                    &db.get(KEY_LAST_ACCEPTED).await.map_err(db_error)?,
                    "stored last accepted ID",
                )?;
                let parsed =
                    parse_block_bytes(db.get(&block_key(last_id)).await.map_err(db_error)?)?;
                if parsed.id != last_id {
                    return Err(internal("stored last accepted block has the wrong ID"));
                }
                let state = State::decode(&db.get(&state_key(last_id)).await.map_err(db_error)?)
                    .map_err(internal)?;
                VerifiedBlock { state, ..parsed }
            }
        };
        let ongoing_sync = match optional_get(&db, KEY_ONGOING_STATE_SYNC).await? {
            Some(bytes) => {
                let summary = StateSummary::decode(&bytes).map_err(internal)?;
                if !summary.matches_chain(request.network_id, chain_id, genesis_hash) {
                    return Err(failed(
                        "persisted state-sync target belongs to another Avalanche chain",
                    ));
                }
                if summary.height <= last_accepted.block.height {
                    return Err(failed(
                        "persisted state-sync target is not ahead of the accepted state",
                    ));
                }
                Some(summary)
            }
            None => None,
        };
        let last_completed_sync = match optional_get(&db, KEY_LAST_COMPLETED_STATE_SYNC).await? {
            Some(bytes) => {
                let summary = StateSummary::decode(&bytes).map_err(internal)?;
                if !summary.matches_chain(request.network_id, chain_id, genesis_hash)
                    || summary.height > last_accepted.block.height
                {
                    return Err(failed(
                        "persisted completed state-sync summary is inconsistent with the chain",
                    ));
                }
                Some(summary)
            }
            None => None,
        };
        let response = initialize_response(&last_accepted);
        let runtime = Runtime {
            db,
            network_id: request.network_id,
            subnet_id,
            chain_id,
            node_id: request.node_id,
            genesis,
            genesis_bytes: request.genesis_bytes,
            authorizer,
            engine_state: wire::State::Bootstrapping,
            preferred: last_accepted.id,
            last_accepted,
            verified: BTreeMap::new(),
            mempool: VecDeque::new(),
            pending: BTreeSet::new(),
            processing: BTreeMap::new(),
            rejected: BTreeMap::new(),
            peers: BTreeSet::new(),
            engine_events: VecDeque::new(),
            ongoing_sync,
            last_completed_sync,
            sync_running: false,
            last_sync_error: None,
            next_app_request_id: 0,
            pending_sync_requests: BTreeMap::new(),
            app_sender,
            api_server_address: None,
            fallback_server_address: None,
            http_servers: Vec::new(),
        };
        self.shutting_down.store(false, Ordering::Release);
        *self.inner.write().await = Some(runtime);
        Ok(Response::new(response))
    }

    async fn set_state(
        &self,
        request: Request<SetStateRequest>,
    ) -> Result<Response<SetStateResponse>, Status> {
        let state = wire::State::try_from(request.into_inner().state)
            .map_err(|_| invalid("unknown Avalanche engine state"))?;
        if state == wire::State::Unspecified {
            return Err(invalid("QOMM VM does not support an unspecified state"));
        }
        let mut guard = self.inner.write().await;
        let runtime = guard
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?;
        runtime.engine_state = state;
        Ok(Response::new(set_state_response(&runtime.last_accepted)))
    }

    async fn shutdown(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        self.shutting_down.store(true, Ordering::Release);
        self.events.notify_waiters();
        let runtime = self.inner.write().await.take();
        if let Some(mut runtime) = runtime {
            for (_, pending) in std::mem::take(&mut runtime.pending_sync_requests) {
                let _ = pending
                    .sender
                    .send(Err("VM shut down during state sync".into()));
            }
            for server in runtime.http_servers.drain(..) {
                server
                    .shutdown()
                    .await
                    .map_err(|error| internal(error.to_string()))?;
            }
            runtime.db.close().await.map_err(db_error)?;
        }
        Ok(Response::new(()))
    }

    async fn create_handlers(
        &self,
        _request: Request<()>,
    ) -> Result<Response<CreateHandlersResponse>, Status> {
        let address = self.get_or_spawn_http_server(true).await?;
        Ok(Response::new(CreateHandlersResponse {
            handlers: vec![Handler {
                prefix: String::new(),
                server_addr: address,
            }],
        }))
    }

    async fn new_http_handler(
        &self,
        _request: Request<()>,
    ) -> Result<Response<NewHttpHandlerResponse>, Status> {
        let address = self.get_or_spawn_http_server(false).await?;
        Ok(Response::new(NewHttpHandlerResponse {
            server_addr: address,
        }))
    }

    async fn wait_for_event(
        &self,
        _request: Request<()>,
    ) -> Result<Response<WaitForEventResponse>, Status> {
        loop {
            if self.shutting_down.load(Ordering::Acquire) {
                return Err(Status::cancelled("VM is shutting down"));
            }
            let notified = self.events.notified();
            let message = {
                let mut guard = self.inner.write().await;
                let runtime = guard
                    .as_mut()
                    .ok_or_else(|| failed("VM is not initialized"))?;
                runtime
                    .engine_events
                    .pop_front()
                    .or_else(|| (!runtime.mempool.is_empty()).then_some(wire::Message::BuildBlock))
            };
            if let Some(message) = message {
                return Ok(Response::new(WaitForEventResponse {
                    message: message as i32,
                }));
            }
            notified.await;
        }
    }

    async fn connected(&self, request: Request<ConnectedRequest>) -> Result<Response<()>, Status> {
        let request = request.into_inner();
        if request.node_id.len() != 20 {
            return Err(invalid("connected peer node ID must contain 20 bytes"));
        }
        let mut guard = self.inner.write().await;
        guard
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?
            .peers
            .insert(request.node_id);
        Ok(Response::new(()))
    }

    async fn disconnected(
        &self,
        request: Request<DisconnectedRequest>,
    ) -> Result<Response<()>, Status> {
        let request = request.into_inner();
        if request.node_id.len() != 20 {
            return Err(invalid("disconnected peer node ID must contain 20 bytes"));
        }
        let mut guard = self.inner.write().await;
        let runtime = guard
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?;
        runtime.peers.remove(&request.node_id);
        let failed_requests = runtime
            .pending_sync_requests
            .iter()
            .filter_map(|(request_id, pending)| {
                (pending.peer == request.node_id).then_some(*request_id)
            })
            .collect::<Vec<_>>();
        for request_id in failed_requests {
            if let Some(pending) = runtime.pending_sync_requests.remove(&request_id) {
                let _ = pending
                    .sender
                    .send(Err("state-sync peer disconnected".into()));
            }
        }
        Ok(Response::new(()))
    }

    async fn build_block(
        &self,
        _request: Request<BuildBlockRequest>,
    ) -> Result<Response<BuildBlockResponse>, Status> {
        loop {
            let preferred = self
                .inner
                .read()
                .await
                .as_ref()
                .ok_or_else(|| failed("VM is not initialized"))?
                .preferred;
            let parent = self.load_block(preferred).await?;
            let mut guard = self.inner.write().await;
            let runtime = guard
                .as_mut()
                .ok_or_else(|| failed("VM is not initialized"))?;
            if runtime.preferred != preferred {
                continue;
            }
            if runtime.engine_state != wire::State::NormalOp {
                return Err(failed("VM is not in normal operation"));
            }
            let mut state = parent.state.clone();
            let block_timestamp = now_seconds().map_err(internal)?.max(parent.block.timestamp);
            let mut transactions = Vec::new();
            let mut receipts = Vec::new();
            while transactions.len() < MAX_TRANSACTIONS {
                let Some(bytes) = runtime.mempool.pop_front() else {
                    break;
                };
                let id = TransactionEnvelope::decode(&bytes)
                    .and_then(|transaction| transaction.id())
                    .map_err(internal)?;
                runtime.pending.remove(&id);
                match state.apply(&bytes, &runtime.authorizer, block_timestamp as u64) {
                    Ok(receipt) => {
                        runtime.processing.insert(id, bytes.clone());
                        transactions.push(bytes);
                        receipts.push(receipt);
                    }
                    Err(reason) if reason.contains("already applied") => {
                        // A peer may win consensus with this gossiped
                        // transaction before the local proposer drains its
                        // copy. It is an accepted duplicate, not an application
                        // rejection; the persisted receipt is authoritative.
                        runtime.rejected.remove(&id);
                    }
                    Err(reason) => {
                        runtime.rejected.insert(id, reason);
                        while runtime.rejected.len() > MAX_REJECTIONS {
                            let oldest = *runtime.rejected.keys().next().expect("non-empty");
                            runtime.rejected.remove(&oldest);
                        }
                    }
                }
            }
            if transactions.is_empty() {
                return Err(failed("no valid pending transactions"));
            }
            let block = Block {
                parent_id: parent.id,
                timestamp: block_timestamp,
                height: parent.block.height.saturating_add(1),
                transactions,
            };
            let bytes = block.encode().map_err(internal)?;
            let id = block.id().map_err(internal)?;
            let verified = VerifiedBlock {
                block,
                bytes,
                id,
                state,
                receipts,
            };
            runtime.verified.insert(id, verified.clone());
            if !runtime.mempool.is_empty() {
                self.events.notify_one();
            }
            return Ok(Response::new(build_response(&verified)));
        }
    }

    async fn parse_block(
        &self,
        request: Request<ParseBlockRequest>,
    ) -> Result<Response<ParseBlockResponse>, Status> {
        let parsed = parse_block_bytes(request.into_inner().bytes)?;
        Ok(Response::new(parse_response(&parsed)))
    }

    async fn get_block(
        &self,
        request: Request<GetBlockRequest>,
    ) -> Result<Response<GetBlockResponse>, Status> {
        let id = parse_id(&request.into_inner().id, "block ID")?;
        match self.load_block(id).await {
            Ok(block) => Ok(Response::new(GetBlockResponse {
                parent_id: block.block.parent_id.0.to_vec(),
                bytes: block.bytes,
                height: block.block.height,
                timestamp: Some(timestamp(block.block.timestamp)),
                err: wire::Error::Unspecified as i32,
                verify_with_context: false,
            })),
            Err(status) if status.code() == tonic::Code::NotFound => {
                Ok(Response::new(GetBlockResponse {
                    parent_id: Vec::new(),
                    bytes: Vec::new(),
                    height: 0,
                    timestamp: None,
                    err: wire::Error::NotFound as i32,
                    verify_with_context: false,
                }))
            }
            Err(status) => Err(status),
        }
    }

    async fn set_preference(
        &self,
        request: Request<SetPreferenceRequest>,
    ) -> Result<Response<()>, Status> {
        let id = parse_id(&request.into_inner().id, "preferred block ID")?;
        self.load_block(id).await?;
        let mut guard = self.inner.write().await;
        guard
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?
            .preferred = id;
        Ok(Response::new(()))
    }

    async fn health(&self, _request: Request<()>) -> Result<Response<HealthResponse>, Status> {
        let (
            db,
            last,
            pending,
            processing,
            peers,
            node_id,
            genesis_bytes,
            ongoing_sync,
            last_completed_sync,
            sync_running,
            last_sync_error,
            pending_sync_requests,
        ) = {
            let guard = self.inner.read().await;
            let runtime = guard
                .as_ref()
                .ok_or_else(|| failed("VM is not initialized"))?;
            (
                runtime.db.clone(),
                runtime.last_accepted.clone(),
                runtime.pending.len(),
                runtime.processing.len(),
                runtime.peers.len(),
                runtime.node_id.clone(),
                runtime.genesis_bytes.len(),
                runtime.ongoing_sync.clone(),
                runtime.last_completed_sync.clone(),
                runtime.sync_running,
                runtime.last_sync_error.clone(),
                runtime.pending_sync_requests.len(),
            )
        };
        db.health_check().await.map_err(db_error)?;
        let details = serde_json::to_vec(&json!({
            "healthy": true,
            "lastAccepted": last.id.to_string(),
            "height": last.block.height,
            "stateRoot": hex::encode(last.state.root()),
            "pending": pending,
            "processing": processing,
            "peers": peers,
            "nodeIDBytes": node_id.len(),
            "genesisBytes": genesis_bytes,
            "stateSync": {
                "enabled": true,
                "running": sync_running,
                "ongoingHeight": ongoing_sync.as_ref().map(|summary| summary.height),
                "ongoingSummaryID": ongoing_sync
                    .as_ref()
                    .and_then(|summary| summary.id().ok())
                    .map(|id| id.to_string()),
                "lastCompletedHeight": last_completed_sync
                    .as_ref()
                    .map(|summary| summary.height),
                "lastCompletedSummaryID": last_completed_sync
                    .as_ref()
                    .and_then(|summary| summary.id().ok())
                    .map(|id| id.to_string()),
                "pendingRequests": pending_sync_requests,
                "lastError": last_sync_error,
            },
        }))
        .map_err(|error| internal(error.to_string()))?;
        Ok(Response::new(HealthResponse { details }))
    }

    async fn version(&self, _request: Request<()>) -> Result<Response<VersionResponse>, Status> {
        Ok(Response::new(VersionResponse {
            version: VERSION.into(),
        }))
    }

    async fn app_request(&self, request: Request<AppRequestMsg>) -> Result<Response<()>, Status> {
        let request = request.into_inner();
        if request.node_id.len() != 20 {
            return Err(invalid("application request node ID must contain 20 bytes"));
        }
        let sender = self
            .inner
            .read()
            .await
            .as_ref()
            .ok_or_else(|| failed("VM is not initialized"))?
            .app_sender
            .clone();
        let response = async {
            if deadline_expired(request.deadline.as_ref())? {
                return Err("state-sync application request deadline has expired".to_string());
            }
            let chunk_request = ChunkRequest::decode(&request.request)?;
            self.validate_state_summary_chain(&chunk_request.summary)
                .await
                .map_err(|status| status.message().to_string())?;
            let snapshot = self
                .local_state_snapshot(&chunk_request.summary)
                .await
                .map_err(|status| status.message().to_string())?;
            ChunkResponse::build(&chunk_request.summary, &snapshot, chunk_request.index)?.encode()
        }
        .await;
        match response {
            Ok(response) => sender
                .send_response(request.node_id, request.request_id, response)
                .await
                .map_err(|error| internal(error.to_string()))?,
            Err(error) => sender
                .send_error(
                    request.node_id,
                    request.request_id,
                    1,
                    error.chars().take(1_024).collect(),
                )
                .await
                .map_err(|error| internal(error.to_string()))?,
        }
        Ok(Response::new(()))
    }

    async fn app_request_failed(
        &self,
        request: Request<AppRequestFailedMsg>,
    ) -> Result<Response<()>, Status> {
        let request = request.into_inner();
        if request.node_id.len() != 20 {
            return Err(invalid(
                "failed application request node ID must contain 20 bytes",
            ));
        }
        let pending = self
            .inner
            .write()
            .await
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?
            .pending_sync_requests
            .remove(&request.request_id);
        if let Some(pending) = pending {
            let result = if pending.peer == request.node_id {
                Err(format!(
                    "state-sync peer returned error {}: {}",
                    request.error_code, request.error_message
                ))
            } else {
                Err("state-sync failure came from the wrong peer".into())
            };
            let _ = pending.sender.send(result);
        }
        Ok(Response::new(()))
    }

    async fn app_response(&self, request: Request<AppResponseMsg>) -> Result<Response<()>, Status> {
        let request = request.into_inner();
        if request.node_id.len() != 20 {
            return Err(invalid(
                "application response node ID must contain 20 bytes",
            ));
        }
        let pending = self
            .inner
            .write()
            .await
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?
            .pending_sync_requests
            .remove(&request.request_id);
        if let Some(pending) = pending {
            let result = if pending.peer == request.node_id {
                Ok(request.response)
            } else {
                Err("state-sync response came from the wrong peer".into())
            };
            let _ = pending.sender.send(result);
        }
        Ok(Response::new(()))
    }

    async fn app_gossip(&self, request: Request<AppGossipMsg>) -> Result<Response<()>, Status> {
        let request = request.into_inner();
        if request.node_id.len() != 20 {
            return Err(invalid("gossip node ID must contain 20 bytes"));
        }
        self.enqueue(request.msg, false).await.map_err(invalid)?;
        Ok(Response::new(()))
    }

    async fn gather(&self, _request: Request<()>) -> Result<Response<GatherResponse>, Status> {
        Ok(Response::new(GatherResponse {
            metric_families: Vec::new(),
        }))
    }

    async fn get_ancestors(
        &self,
        request: Request<GetAncestorsRequest>,
    ) -> Result<Response<GetAncestorsResponse>, Status> {
        let request = request.into_inner();
        if request.max_blocks_num <= 0 || request.max_blocks_size <= 0 {
            return Ok(Response::new(GetAncestorsResponse {
                blks_bytes: Vec::new(),
            }));
        }
        let mut id = parse_id(&request.blk_id, "ancestor block ID")?;
        let maximum = usize::try_from(request.max_blocks_num)
            .unwrap_or(MAX_ANCESTORS)
            .min(MAX_ANCESTORS);
        let maximum_bytes = usize::try_from(request.max_blocks_size)
            .unwrap_or(MAX_BLOCK_BYTES)
            .min(avalanche_rpcchainvm_qomm::DEFAULT_MAX_MESSAGE_BYTES);
        let time_limit = if request.max_blocks_retrival_time <= 0 {
            Duration::ZERO
        } else {
            Duration::from_nanos(request.max_blocks_retrival_time as u64)
        };
        let started = Instant::now();
        let mut result = Vec::new();
        let mut size = 0usize;
        for _ in 0..maximum {
            if !time_limit.is_zero() && started.elapsed() >= time_limit {
                break;
            }
            let block = match self.load_block(id).await {
                Ok(block) => block,
                Err(status) if status.code() == tonic::Code::NotFound => break,
                Err(status) => return Err(status),
            };
            if size.saturating_add(block.bytes.len()) > maximum_bytes {
                break;
            }
            size += block.bytes.len();
            id = block.block.parent_id;
            let height = block.block.height;
            result.push(block.bytes);
            if height == 0 {
                break;
            }
        }
        Ok(Response::new(GetAncestorsResponse { blks_bytes: result }))
    }

    async fn batched_parse_block(
        &self,
        request: Request<BatchedParseBlockRequest>,
    ) -> Result<Response<BatchedParseBlockResponse>, Status> {
        let request = request.into_inner();
        if request.request.len() > MAX_ANCESTORS {
            return Err(invalid("batched block parse exceeds the block-count limit"));
        }
        let mut response = Vec::with_capacity(request.request.len());
        for bytes in request.request {
            response.push(parse_response(&parse_block_bytes(bytes)?));
        }
        Ok(Response::new(BatchedParseBlockResponse { response }))
    }

    async fn get_block_id_at_height(
        &self,
        request: Request<GetBlockIdAtHeightRequest>,
    ) -> Result<Response<GetBlockIdAtHeightResponse>, Status> {
        let db = self.database().await?;
        match optional_get(&db, &height_key(request.into_inner().height)).await? {
            Some(bytes) => Ok(Response::new(GetBlockIdAtHeightResponse {
                blk_id: parse_id(&bytes, "stored height index")?.0.to_vec(),
                err: wire::Error::Unspecified as i32,
            })),
            None => Ok(Response::new(GetBlockIdAtHeightResponse {
                blk_id: Vec::new(),
                err: wire::Error::NotFound as i32,
            })),
        }
    }

    async fn state_sync_enabled(
        &self,
        _request: Request<()>,
    ) -> Result<Response<StateSyncEnabledResponse>, Status> {
        Ok(Response::new(StateSyncEnabledResponse {
            enabled: true,
            err: wire::Error::Unspecified as i32,
        }))
    }

    async fn get_ongoing_sync_state_summary(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GetOngoingSyncStateSummaryResponse>, Status> {
        let summary = self
            .inner
            .read()
            .await
            .as_ref()
            .ok_or_else(|| failed("VM is not initialized"))?
            .ongoing_sync
            .clone();
        match summary {
            Some(summary) => Ok(Response::new(GetOngoingSyncStateSummaryResponse {
                id: summary.id().map_err(internal)?.0.to_vec(),
                height: summary.height,
                bytes: summary.encode().map_err(internal)?,
                err: wire::Error::Unspecified as i32,
            })),
            None => Ok(Response::new(GetOngoingSyncStateSummaryResponse {
                id: Vec::new(),
                height: 0,
                bytes: Vec::new(),
                err: wire::Error::NotFound as i32,
            })),
        }
    }

    async fn get_last_state_summary(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GetLastStateSummaryResponse>, Status> {
        let last = self
            .inner
            .read()
            .await
            .as_ref()
            .ok_or_else(|| failed("VM is not initialized"))?
            .last_accepted
            .clone();
        let (summary, _) = self.state_summary_for(&last).await?;
        Ok(Response::new(GetLastStateSummaryResponse {
            id: summary.id().map_err(internal)?.0.to_vec(),
            height: summary.height,
            bytes: summary.encode().map_err(internal)?,
            err: wire::Error::Unspecified as i32,
        }))
    }

    async fn parse_state_summary(
        &self,
        request: Request<ParseStateSummaryRequest>,
    ) -> Result<Response<ParseStateSummaryResponse>, Status> {
        let summary = StateSummary::decode(&request.into_inner().bytes).map_err(invalid)?;
        self.validate_state_summary_chain(&summary).await?;
        Ok(Response::new(ParseStateSummaryResponse {
            id: summary.id().map_err(internal)?.0.to_vec(),
            height: summary.height,
            err: wire::Error::Unspecified as i32,
        }))
    }

    async fn get_state_summary(
        &self,
        request: Request<GetStateSummaryRequest>,
    ) -> Result<Response<GetStateSummaryResponse>, Status> {
        let db = self.database().await?;
        let Some(id) = optional_get(&db, &height_key(request.into_inner().height)).await? else {
            return Ok(Response::new(GetStateSummaryResponse {
                id: Vec::new(),
                bytes: Vec::new(),
                err: wire::Error::NotFound as i32,
            }));
        };
        let block = self
            .load_block(parse_id(&id, "stored height index")?)
            .await?;
        let (summary, _) = self.state_summary_for(&block).await?;
        Ok(Response::new(GetStateSummaryResponse {
            id: summary.id().map_err(internal)?.0.to_vec(),
            bytes: summary.encode().map_err(internal)?,
            err: wire::Error::Unspecified as i32,
        }))
    }

    async fn block_verify(
        &self,
        request: Request<BlockVerifyRequest>,
    ) -> Result<Response<BlockVerifyResponse>, Status> {
        let verified = self.verify_candidate(request.into_inner().bytes).await?;
        Ok(Response::new(BlockVerifyResponse {
            timestamp: Some(timestamp(verified.block.timestamp)),
        }))
    }

    async fn block_accept(
        &self,
        request: Request<BlockAcceptRequest>,
    ) -> Result<Response<()>, Status> {
        let id = parse_id(&request.into_inner().id, "accepted block ID")?;
        // Acceptance is a single critical section. Keeping the verified block
        // indexed until the database batch succeeds prevents a transient DB
        // error from making a valid block impossible to retry. Serializing the
        // DB write with the in-memory tip update also prevents two competing
        // children from both committing against the same parent.
        let mut guard = self.inner.write().await;
        let runtime = guard
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?;
        let block = runtime
            .verified
            .get(&id)
            .cloned()
            .ok_or_else(|| failed("accepted block was not verified"))?;
        if block.block.parent_id != runtime.last_accepted.id
            || block.block.height != runtime.last_accepted.block.height.saturating_add(1)
        {
            return Err(failed(
                "accepted block does not extend the last accepted block",
            ));
        }
        let mut operations = vec![
            BatchOp::Put {
                key: KEY_LAST_ACCEPTED.to_vec(),
                value: id.0.to_vec(),
            },
            BatchOp::Put {
                key: block_key(id),
                value: block.bytes.clone(),
            },
            BatchOp::Put {
                key: state_key(id),
                value: block.state.encode().map_err(internal)?,
            },
            BatchOp::Put {
                key: height_key(block.block.height),
                value: id.0.to_vec(),
            },
        ];
        for receipt in &block.receipts {
            let accepted = AcceptedReceipt {
                transaction_id: receipt.transaction_id.0,
                block_id: id.0,
                height: block.block.height,
                statement: receipt.statement,
                before_root: receipt.before_root,
                after_root: receipt.after_root,
            };
            operations.push(BatchOp::Put {
                key: transaction_key(receipt.transaction_id),
                value: serde_json::to_vec(&accepted)
                    .map_err(|error| internal(error.to_string()))?,
            });
        }
        runtime
            .db
            .write_batch(&operations)
            .await
            .map_err(db_error)?;
        runtime.verified.remove(&id);
        let accepted_transactions = block
            .receipts
            .iter()
            .map(|receipt| receipt.transaction_id)
            .collect::<BTreeSet<_>>();
        runtime.mempool.retain(|bytes| {
            TransactionEnvelope::decode(bytes)
                .and_then(|transaction| transaction.id())
                .is_ok_and(|transaction_id| !accepted_transactions.contains(&transaction_id))
        });
        for receipt in &block.receipts {
            runtime.pending.remove(&receipt.transaction_id);
            runtime.processing.remove(&receipt.transaction_id);
            runtime.rejected.remove(&receipt.transaction_id);
        }
        runtime.last_accepted = block;
        runtime.preferred = id;
        Ok(Response::new(()))
    }

    async fn block_reject(
        &self,
        request: Request<BlockRejectRequest>,
    ) -> Result<Response<()>, Status> {
        let id = parse_id(&request.into_inner().id, "rejected block ID")?;
        let mut guard = self.inner.write().await;
        let runtime = guard
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?;
        let block = runtime
            .verified
            .remove(&id)
            .ok_or_else(|| failed("rejected block was not verified"))?;
        for transaction in block.block.transactions.into_iter().rev() {
            let envelope = TransactionEnvelope::decode(&transaction).map_err(internal)?;
            let transaction_id = envelope.id().map_err(internal)?;
            runtime.processing.remove(&transaction_id);
            if !runtime
                .last_accepted
                .state
                .applied_transactions
                .contains(&transaction_id.0)
                && runtime.pending.insert(transaction_id)
            {
                runtime.mempool.push_front(transaction);
            }
        }
        if !runtime.mempool.is_empty() {
            self.events.notify_one();
        }
        Ok(Response::new(()))
    }

    async fn state_summary_accept(
        &self,
        request: Request<StateSummaryAcceptRequest>,
    ) -> Result<Response<StateSummaryAcceptResponse>, Status> {
        let summary = StateSummary::decode(&request.into_inner().bytes).map_err(invalid)?;
        self.validate_state_summary_chain(&summary).await?;
        let mut guard = self.inner.write().await;
        let runtime = guard
            .as_mut()
            .ok_or_else(|| failed("VM is not initialized"))?;
        if summary.height <= runtime.last_accepted.block.height {
            return Ok(Response::new(StateSummaryAcceptResponse {
                mode: state_summary_accept_response::Mode::Skipped as i32,
                err: wire::Error::Unspecified as i32,
            }));
        }
        if runtime.sync_running {
            let mode = if runtime.ongoing_sync.as_ref() == Some(&summary) {
                state_summary_accept_response::Mode::Static
            } else {
                state_summary_accept_response::Mode::Skipped
            };
            return Ok(Response::new(StateSummaryAcceptResponse {
                mode: mode as i32,
                err: wire::Error::Unspecified as i32,
            }));
        }
        let mut operations = Vec::new();
        if let Some(previous) = runtime.ongoing_sync.as_ref() {
            if previous != &summary {
                let previous_id = previous.id().map_err(internal)?;
                for index in 0..previous.chunk_count {
                    operations.push(BatchOp::Delete {
                        key: state_sync_chunk_key(previous_id, index),
                    });
                }
            }
        }
        operations.push(BatchOp::Put {
            key: KEY_ONGOING_STATE_SYNC.to_vec(),
            value: summary.encode().map_err(internal)?,
        });
        runtime
            .db
            .write_batch(&operations)
            .await
            .map_err(db_error)?;
        runtime.ongoing_sync = Some(summary.clone());
        runtime.sync_running = true;
        runtime.last_sync_error = None;
        drop(guard);
        let vm = self.clone();
        tokio::spawn(async move {
            vm.finish_state_sync(summary).await;
        });
        Ok(Response::new(StateSummaryAcceptResponse {
            mode: state_summary_accept_response::Mode::Static as i32,
            err: wire::Error::Unspecified as i32,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_keys_are_binary_and_prefix_stable() {
        let id = Id([7; 32]);
        assert_eq!(&block_key(id)[..PREFIX_BLOCK.len()], PREFIX_BLOCK);
        assert_eq!(&height_key(42)[PREFIX_HEIGHT.len()..], &42u64.to_be_bytes());
        assert_ne!(block_key(id), state_key(id));
    }

    #[test]
    fn json_rpc_parse_errors_have_the_standard_code() {
        let (_, body) = rpc_error(Value::Null, -32700, "bad".into());
        let value: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(value["error"]["code"], -32700);
    }

    #[test]
    fn textual_ids_accept_cb58_and_hex() {
        let id = Id([9; 32]);
        assert_eq!(parse_text_id(&id.to_string(), "id").expect("CB58"), id);
        assert_eq!(parse_text_id(&hex::encode(id.0), "id").expect("hex"), id);
    }

    #[test]
    fn settlement_verifier_snapshot_returns_the_canonical_restart_anchor() {
        use qomm_defmi::settlement_verifier::SettlementVerifierConfig;
        use qomm_zkpi::deal_quorum;
        use rand_core::OsRng;

        let (_, public) = deal_quorum(7, 3, &mut OsRng).expect("FROST group");
        let config = SettlementVerifierConfig {
            venue_id: [41; 32],
            defmi_id: [42; 32],
            epoch: 43,
            quote_registry_digest: [44; 32],
            quote_eligibility_bits: 46,
            quote_span_bits: 48,
            amount_bits: 16,
            price_bits: 32,
            max_horizon: 3_600,
            frost_public_package: public.serialize().expect("public package"),
            valid_from: 1,
            valid_until: 4_102_444_800,
        };
        let statement = config.statement().expect("verifier statement");
        let mut state = State::default();
        state.settlement_verifiers.insert(
            id_key(&config.key()),
            crate::state::SettlementVerifierRecord {
                venue_id: config.venue_id,
                defmi_id: config.defmi_id,
                epoch: config.epoch,
                quote_registry_digest: config.quote_registry_digest,
                quote_eligibility_bits: config.quote_eligibility_bits,
                quote_span_bits: config.quote_span_bits,
                amount_bits: config.amount_bits,
                price_bits: config.price_bits,
                max_horizon: config.max_horizon,
                frost_public_package: config.frost_public_package.clone(),
                valid_from: config.valid_from,
                valid_until: config.valid_until,
                statement,
            },
        );

        let snapshot = canonical_state_snapshot(
            &state,
            "defmivm.settlementVerifier",
            &json!({"venueID": hex::encode(config.venue_id), "epoch": config.epoch}),
            9,
            10,
            Id([45; 32]),
        )
        .unwrap_or_else(|_| panic!("settlement verifier snapshot failed"));
        assert_eq!(snapshot["stateRoot"], hex::encode(state.root()));
        assert_eq!(snapshot["statement"], hex::encode(statement));
        assert_eq!(snapshot["quoteRegistryDigest"], hex::encode([44; 32]));
        assert_eq!(snapshot["epoch"], 43);
    }

    #[test]
    fn admission_cursor_returns_the_next_canonical_venue_epoch_sequence() {
        use crate::state::{admission_entry_key, AdmissionBatchRecord, AdmissionEntryRecord};

        let venue_id = [46; 32];
        let epoch = 47;
        let batch_id = [48; 32];
        let mut state = State::default();
        state.admission_batches.insert(
            id_key(&batch_id),
            AdmissionBatchRecord {
                venue_id,
                epoch,
                slot: 99,
                batch_digest: [49; 32],
                order_digest: [50; 32],
                population: 1,
                consumed: 0,
                expires_at: 4_102_444_800,
                statement: [51; 32],
            },
        );
        state.admission_entries.insert(
            admission_entry_key(&batch_id, 7),
            AdmissionEntryRecord {
                batch_id,
                sequence: 7,
                admission_digest: [52; 32],
                consumed_by: [0; 32],
            },
        );

        let snapshot = canonical_state_snapshot(
            &state,
            "defmivm.admissionCursor",
            &json!({"venueID": hex::encode(venue_id), "epoch": epoch}),
            9,
            10,
            Id([53; 32]),
        )
        .unwrap_or_else(|_| panic!("admission cursor snapshot failed"));
        assert_eq!(snapshot["stateRoot"], hex::encode(state.root()));
        assert_eq!(snapshot["venueID"], hex::encode(venue_id));
        assert_eq!(snapshot["epoch"], epoch);
        assert_eq!(snapshot["lastSequence"], 7);
        assert_eq!(snapshot["nextSequence"], 8);
    }

    #[test]
    fn note_claim_pages_filter_by_source_or_recipient_and_advance_the_cursor() {
        use crate::state::{EncryptedOpeningShareRecord, NoteClaimRecord, OpeningEnvelopeRecord};
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
        use curve25519_dalek::scalar::Scalar;

        let source_a = [61; 32];
        let source_b = [62; 32];
        let recipient_a = (G * Scalar::from(71_u64)).compress().to_bytes();
        let recipient_b = (G * Scalar::from(72_u64)).compress().to_bytes();
        let opening = |recipient_view| OpeningEnvelopeRecord {
            context: [63; 32],
            threshold: 1,
            recipient_view,
            shares: vec![EncryptedOpeningShareRecord {
                party: 1,
                ephemeral: (G * Scalar::from(73_u64)).compress().to_bytes(),
                masked_value: Scalar::from(74_u64).to_bytes(),
                masked_blinding: Scalar::from(75_u64).to_bytes(),
            }],
        };
        let record = |source_hold_id, recipient_view| NoteClaimRecord {
            asset_id: [64; 32],
            value_commitment: (G * Scalar::from(76_u64)).compress().to_bytes(),
            recipient_commitment: [65; 32],
            source_hold_id,
            kind: "refund".into(),
            opening_envelope: opening(recipient_view),
            status: "active".into(),
            settlement_digest: [66; 32],
            materialization: [0; 32],
        };
        let mut state = State::default();
        state
            .note_claims
            .insert(id_key(&[1; 32]), record(source_a, recipient_a));
        state
            .note_claims
            .insert(id_key(&[2; 32]), record(source_a, recipient_b));
        state
            .note_claims
            .insert(id_key(&[3; 32]), record(source_b, recipient_a));

        let first = canonical_state_snapshot(
            &state,
            "defmivm.listNoteClaims",
            &json!({
                "sourceHoldID": hex::encode(source_a),
                "after": "",
                "limit": 1,
            }),
            4,
            5,
            Id([67; 32]),
        )
        .unwrap_or_else(|_| panic!("first source page failed"));
        assert_eq!(first["claims"].as_array().unwrap().len(), 1);
        assert_eq!(first["next"], hex::encode([1; 32]));
        let second = canonical_state_snapshot(
            &state,
            "defmivm.listNoteClaims",
            &json!({
                "sourceHoldID": hex::encode(source_a),
                "after": first["next"],
                "limit": 2,
            }),
            4,
            5,
            Id([67; 32]),
        )
        .unwrap_or_else(|_| panic!("second source page failed"));
        assert_eq!(second["claims"].as_array().unwrap().len(), 1);
        assert_eq!(second["claims"][0]["claimID"], hex::encode([2; 32]));

        let recipient = canonical_state_snapshot(
            &state,
            "defmivm.listNoteClaims",
            &json!({
                "recipientView": hex::encode(recipient_a),
                "after": "",
                "limit": 8,
            }),
            4,
            5,
            Id([67; 32]),
        )
        .unwrap_or_else(|_| panic!("recipient page failed"));
        assert_eq!(recipient["claims"].as_array().unwrap().len(), 2);
        assert!(canonical_state_snapshot(
            &state,
            "defmivm.listNoteClaims",
            &json!({
                "sourceHoldID": hex::encode(source_a),
                "recipientView": hex::encode(recipient_a),
            }),
            4,
            5,
            Id([67; 32]),
        )
        .is_err());
    }

    #[test]
    fn participant_snapshots_expose_capabilities_but_not_canonical_balances() {
        use std::collections::BTreeSet;

        use ed25519_dalek::SigningKey;
        use qomm_defmi::participant::{
            ParticipantKeys, ParticipantRecord, ParticipantRole, ParticipantStatus, PurposeKey,
            RegisterParticipant, RegistryConfiguration,
        };

        let key = |value: u8| PurposeKey {
            public_key: SigningKey::from_bytes(&[value; 32])
                .verifying_key()
                .to_bytes(),
            epoch: 1,
        };
        let participant_id = [20; 32];
        let mut state = State::default();
        state
            .participant_registry
            .configure(RegistryConfiguration {
                operation_id: [1; 32],
                domain_id: [2; 32],
                template_digest: [3; 32],
                schema_digest: [4; 32],
                template_version: 1,
            })
            .expect("configuration");
        state
            .participant_registry
            .register_participant(
                RegisterParticipant {
                    operation_id: [5; 32],
                    participant: ParticipantRecord {
                        participant_id,
                        legal_entity_credential_commitment: [6; 32],
                        credential_issuer_id: [7; 32],
                        credential_scheme_digest: [8; 32],
                        jurisdiction: "JP".into(),
                        roles: [ParticipantRole::BrokerDealer, ParticipantRole::Maker]
                            .into_iter()
                            .collect::<BTreeSet<_>>(),
                        keys: ParticipantKeys {
                            admin: key(10),
                            settlement: key(11),
                            quote: key(12),
                            mpc_input: key(13),
                            emergency: key(14),
                        },
                        policy_digest: [9; 32],
                        valid_from: 10,
                        valid_until: 100,
                        sequence: 0,
                        status: ParticipantStatus::Active,
                    },
                },
                20,
            )
            .expect("participant");

        let summary = canonical_state_snapshot(
            &state,
            "defmivm.participantRegistry",
            &json!({}),
            3,
            20,
            Id([15; 32]),
        )
        .unwrap_or_else(|_| panic!("participant registry summary failed"));
        assert_eq!(summary["participantCount"], 1);
        assert_eq!(summary["status"]["active"], 1);

        let detail = canonical_state_snapshot(
            &state,
            "defmivm.participant",
            &json!({"participantID": hex::encode(participant_id)}),
            3,
            20,
            Id([15; 32]),
        )
        .unwrap_or_else(|_| panic!("participant detail failed"));
        assert_eq!(detail["status"], "active");
        assert_eq!(detail["keys"]["settlement"]["epoch"], 1);
        assert!(detail.get("balance").is_none());
        assert!(detail.get("accountNumber").is_none());
    }
}
