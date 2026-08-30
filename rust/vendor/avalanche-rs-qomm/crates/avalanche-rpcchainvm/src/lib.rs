//! Maintained Rust bindings for AvalancheGo's RPCChainVM protocol 45.
//!
//! The upstream `avalanche-rs` SDK currently emits protocol 33. This focused
//! fork keeps the generated wire contract separate from QOMM's state machine,
//! so a protocol upgrade cannot silently alter financial transition logic.

pub const PROTOCOL_VERSION: u32 = 45;

/// Upper bound used by the compatibility layer for any single gRPC message.
///
/// Avalanche blocks are much smaller than this. The extra headroom is needed
/// for database batches and genesis data while still avoiding the unbounded
/// allocations used by the historical SDK implementation.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("rpcchainvm_descriptor");

pub mod app_sender;
pub mod database;
pub mod http_bridge;
pub mod plugin;
