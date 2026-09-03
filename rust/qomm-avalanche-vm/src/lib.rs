//! QOMM's non-EVM Avalanche virtual machine.

pub mod block;
mod execution;
pub mod genesis;
pub mod id;
pub mod state;
pub mod state_sync;
pub mod transaction;
pub mod vm;

pub const VERSION: &str = "qomm-avalanche-vm/0.1.0";

pub use vm::QommVm;
