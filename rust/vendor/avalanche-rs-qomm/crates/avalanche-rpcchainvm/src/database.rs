//! AvalancheGo-owned key/value database client.
//!
//! RPCChainVM gives each VM a private database server address during
//! `Initialize`. Keeping this client in the protocol fork means QOMM's state
//! machine never depends on AvalancheGo's Go packages or in-process ABI.

use std::{
    collections::{BTreeMap, VecDeque},
    error::Error as StdError,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tonic::transport::{Channel, Endpoint};

use crate::{
    pb::rpcdb::{
        database_client::DatabaseClient as RpcDatabaseClient, CloseRequest, CompactRequest,
        DeleteRequest, Error as RpcError, GetRequest, HasRequest, IteratorErrorRequest,
        IteratorNextRequest, IteratorReleaseRequest, NewIteratorWithStartAndPrefixRequest,
        PutRequest, WriteBatchRequest,
    },
    DEFAULT_MAX_MESSAGE_BYTES,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A database operation to commit atomically through AvalancheGo's rpcdb.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

/// Errors returned by AvalancheGo's database service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DbError {
    Closed,
    NotFound,
    InvalidRemoteCode(i32),
    MessageTooLarge { actual: usize, maximum: usize },
    Transport(String),
    Remote(String),
}

impl DbError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("Avalanche database is closed"),
            Self::NotFound => formatter.write_str("Avalanche database key was not found"),
            Self::InvalidRemoteCode(code) => {
                write!(
                    formatter,
                    "Avalanche database returned unknown error code {code}"
                )
            }
            Self::MessageTooLarge { actual, maximum } => write!(
                formatter,
                "Avalanche database message is too large ({actual} bytes > {maximum} bytes)"
            ),
            Self::Transport(message) => {
                write!(formatter, "Avalanche database transport: {message}")
            }
            Self::Remote(message) => write!(formatter, "Avalanche database RPC: {message}"),
        }
    }
}

impl StdError for DbError {}

fn decode_error(code: i32) -> Result<(), DbError> {
    match RpcError::try_from(code) {
        Ok(RpcError::Unspecified) => Ok(()),
        Ok(RpcError::Closed) => Err(DbError::Closed),
        Ok(RpcError::NotFound) => Err(DbError::NotFound),
        Err(_) => Err(DbError::InvalidRemoteCode(code)),
    }
}

fn status_error(status: tonic::Status) -> DbError {
    match status.code() {
        tonic::Code::NotFound => DbError::NotFound,
        tonic::Code::FailedPrecondition
            if status.message().to_ascii_lowercase().contains("closed") =>
        {
            DbError::Closed
        }
        _ => DbError::Remote(format!("{}: {}", status.code(), status.message())),
    }
}

/// Cloneable async client for the database server owned by AvalancheGo.
#[derive(Clone)]
pub struct Database {
    inner: RpcDatabaseClient<Channel>,
    closed: Arc<AtomicBool>,
    max_message_bytes: usize,
}

impl Database {
    /// Connects to the raw `host:port` address supplied in `InitializeRequest`.
    pub async fn connect(address: &str) -> Result<Self, DbError> {
        Self::connect_with_limit(address, DEFAULT_MAX_MESSAGE_BYTES).await
    }

    pub async fn connect_with_limit(
        address: &str,
        max_message_bytes: usize,
    ) -> Result<Self, DbError> {
        let uri = if address.starts_with("http://") || address.starts_with("https://") {
            address.to_owned()
        } else {
            format!("http://{address}")
        };
        let endpoint = Endpoint::from_shared(uri)
            .map_err(|error| DbError::Transport(error.to_string()))?
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT);
        let channel = endpoint
            .connect()
            .await
            .map_err(|error| DbError::Transport(error.to_string()))?;
        Ok(Self::from_channel(channel, max_message_bytes))
    }

    pub fn from_channel(channel: Channel, max_message_bytes: usize) -> Self {
        let inner = RpcDatabaseClient::new(channel)
            .max_decoding_message_size(max_message_bytes)
            .max_encoding_message_size(max_message_bytes);
        Self {
            inner,
            closed: Arc::new(AtomicBool::new(false)),
            max_message_bytes,
        }
    }

    fn ensure_open(&self) -> Result<(), DbError> {
        if self.closed.load(Ordering::Acquire) {
            Err(DbError::Closed)
        } else {
            Ok(())
        }
    }

    fn ensure_size(&self, actual: usize) -> Result<(), DbError> {
        if actual > self.max_message_bytes {
            Err(DbError::MessageTooLarge {
                actual,
                maximum: self.max_message_bytes,
            })
        } else {
            Ok(())
        }
    }

    pub async fn has(&self, key: &[u8]) -> Result<bool, DbError> {
        self.ensure_open()?;
        self.ensure_size(key.len())?;
        let response = self
            .inner
            .clone()
            .has(HasRequest { key: key.to_vec() })
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)?;
        Ok(response.has)
    }

    pub async fn get(&self, key: &[u8]) -> Result<Vec<u8>, DbError> {
        self.ensure_open()?;
        self.ensure_size(key.len())?;
        let response = self
            .inner
            .clone()
            .get(GetRequest { key: key.to_vec() })
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)?;
        self.ensure_size(response.value.len())?;
        Ok(response.value)
    }

    pub async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        self.ensure_open()?;
        self.ensure_size(key.len().saturating_add(value.len()))?;
        let response = self
            .inner
            .clone()
            .put(PutRequest {
                key: key.to_vec(),
                value: value.to_vec(),
            })
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)
    }

    pub async fn delete(&self, key: &[u8]) -> Result<(), DbError> {
        self.ensure_open()?;
        self.ensure_size(key.len())?;
        let response = self
            .inner
            .clone()
            .delete(DeleteRequest { key: key.to_vec() })
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)
    }

    /// Atomically commits the final operation for each key.
    ///
    /// rpcdb serializes puts and deletes in separate arrays, so retaining raw
    /// duplicate operations would make their ordering ambiguous. Normalizing
    /// to the last operation makes the Rust-side semantics explicit.
    pub async fn write_batch(&self, operations: &[BatchOp]) -> Result<(), DbError> {
        self.ensure_open()?;
        let mut normalized = BTreeMap::<Vec<u8>, Option<Vec<u8>>>::new();
        let mut encoded_size = 0usize;
        for operation in operations {
            match operation {
                BatchOp::Put { key, value } => {
                    encoded_size = encoded_size
                        .saturating_add(key.len())
                        .saturating_add(value.len());
                    normalized.insert(key.clone(), Some(value.clone()));
                }
                BatchOp::Delete { key } => {
                    encoded_size = encoded_size.saturating_add(key.len());
                    normalized.insert(key.clone(), None);
                }
            }
        }
        self.ensure_size(encoded_size)?;
        let mut request = WriteBatchRequest {
            puts: Vec::new(),
            deletes: Vec::new(),
        };
        for (key, value) in normalized {
            match value {
                Some(value) => request.puts.push(PutRequest { key, value }),
                None => request.deletes.push(DeleteRequest { key }),
            }
        }
        let response = self
            .inner
            .clone()
            .write_batch(request)
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)
    }

    pub async fn compact(&self, start: &[u8], limit: &[u8]) -> Result<(), DbError> {
        self.ensure_open()?;
        self.ensure_size(start.len().saturating_add(limit.len()))?;
        let response = self
            .inner
            .clone()
            .compact(CompactRequest {
                start: start.to_vec(),
                limit: limit.to_vec(),
            })
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)
    }

    pub async fn health_check(&self) -> Result<Vec<u8>, DbError> {
        self.ensure_open()?;
        let response = self
            .inner
            .clone()
            .health_check(())
            .await
            .map_err(status_error)?
            .into_inner();
        self.ensure_size(response.details.len())?;
        Ok(response.details)
    }

    pub async fn iterator(&self, start: &[u8], prefix: &[u8]) -> Result<DatabaseIterator, DbError> {
        self.ensure_open()?;
        self.ensure_size(start.len().saturating_add(prefix.len()))?;
        let response = self
            .inner
            .clone()
            .new_iterator_with_start_and_prefix(NewIteratorWithStartAndPrefixRequest {
                start: start.to_vec(),
                prefix: prefix.to_vec(),
            })
            .await
            .map_err(status_error)?
            .into_inner();
        Ok(DatabaseIterator {
            id: response.id,
            inner: self.inner.clone(),
            pending: VecDeque::new(),
            exhausted: false,
            released: false,
            max_message_bytes: self.max_message_bytes,
        })
    }

    pub async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, DbError> {
        let mut iterator = self.iterator(&[], prefix).await?;
        let mut entries = Vec::new();
        while let Some(entry) = iterator.next().await? {
            entries.push(entry);
        }
        iterator.release().await?;
        Ok(entries)
    }

    pub async fn close(&self) -> Result<(), DbError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let response = self
            .inner
            .clone()
            .close(CloseRequest {})
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)
    }
}

/// Remote iterator whose resources must be explicitly released.
pub struct DatabaseIterator {
    id: u64,
    inner: RpcDatabaseClient<Channel>,
    pending: VecDeque<PutRequest>,
    exhausted: bool,
    released: bool,
    max_message_bytes: usize,
}

impl DatabaseIterator {
    pub async fn next(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, DbError> {
        if self.released || self.exhausted {
            return Ok(None);
        }
        if let Some(entry) = self.pending.pop_front() {
            return Ok(Some((entry.key, entry.value)));
        }
        let response = self
            .inner
            .clone()
            .iterator_next(IteratorNextRequest { id: self.id })
            .await
            .map_err(status_error)?
            .into_inner();
        if response.data.is_empty() {
            self.exhausted = true;
            self.check_error().await?;
            return Ok(None);
        }
        let actual = response.data.iter().fold(0usize, |size, entry| {
            size.saturating_add(entry.key.len())
                .saturating_add(entry.value.len())
        });
        if actual > self.max_message_bytes {
            return Err(DbError::MessageTooLarge {
                actual,
                maximum: self.max_message_bytes,
            });
        }
        self.pending = response.data.into();
        self.pending
            .pop_front()
            .map(|entry| Some((entry.key, entry.value)))
            .ok_or_else(|| DbError::Remote("iterator returned an empty page".to_owned()))
    }

    pub async fn check_error(&self) -> Result<(), DbError> {
        let response = self
            .inner
            .clone()
            .iterator_error(IteratorErrorRequest { id: self.id })
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)
    }

    pub async fn release(&mut self) -> Result<(), DbError> {
        if self.released {
            return Ok(());
        }
        let response = self
            .inner
            .clone()
            .iterator_release(IteratorReleaseRequest { id: self.id })
            .await
            .map_err(status_error)?
            .into_inner();
        decode_error(response.err)?;
        self.released = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_rpc_error_codes_without_falling_through() {
        assert_eq!(decode_error(RpcError::Unspecified as i32), Ok(()));
        assert_eq!(decode_error(RpcError::Closed as i32), Err(DbError::Closed));
        assert_eq!(
            decode_error(RpcError::NotFound as i32),
            Err(DbError::NotFound)
        );
        assert_eq!(decode_error(999), Err(DbError::InvalidRemoteCode(999)));
    }

    #[test]
    fn exposes_not_found_classification() {
        assert!(DbError::NotFound.is_not_found());
        assert!(!DbError::Closed.is_not_found());
    }
}
