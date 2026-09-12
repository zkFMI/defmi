//! QOMM's non-EVM Avalanche virtual machine.

pub mod application;
pub mod block;
mod execution;
pub mod genesis;
pub mod id;
pub mod recovery;
#[cfg(feature = "research-cocode")]
pub mod research_cocode;
pub mod state;
mod state_store;
pub mod state_sync;
pub mod transaction;
pub mod vm;

pub const VERSION: &str = "qomm-avalanche-vm/0.1.0";

pub use vm::QommVm;

/// Serve a configured consensus host over Avalanche RPCChainVM.
pub async fn serve(vm: QommVm) -> Result<(), String> {
    avalanche_rpcchainvm_qomm::plugin::serve(vm)
        .await
        .map_err(|error| error.to_string())
}
