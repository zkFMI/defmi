//! Atomic, non-extractable groups of application fills. The per-fill FROST
//! certificates bind group membership before submission; a batch envelope
//! alone is not an authorization to extract or reorder its members.

use super::{ApplicationNoteFill, ZERO};
use crate::application_reservation::ApplicationReserveScope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_APPLICATION_BATCH_FILLS: usize = 8;
/// Leave room for the RPC/transaction envelope inside the VM's 1 MiB limit.
pub const MAX_APPLICATION_BATCH_BYTES: usize = (1 << 20) - 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationFillBatchBinding {
    pub group: [u8; 32],
    pub index: u16,
    pub count: u16,
}

impl ApplicationFillBatchBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.group == ZERO
            || self.count < 2
            || usize::from(self.count) > MAX_APPLICATION_BATCH_FILLS
            || self.index >= self.count
        {
            return Err("application fill batch binding is malformed".into());
        }
        Ok(())
    }
}

pub fn application_fill_group(
    scope: &ApplicationReserveScope,
    before_root: [u8; 32],
    operations: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    scope.validate()?;
    if before_root == ZERO
        || operations.len() < 2
        || operations.len() > MAX_APPLICATION_BATCH_FILLS
        || operations.contains(&ZERO)
        || operations.iter().collect::<BTreeSet<_>>().len() != operations.len()
    {
        return Err("application fill group has invalid parent, size or repeated operation".into());
    }
    let mut hash = Sha256::new()
        .chain_update(b"DEFMI:APPLICATION:FILL-GROUP:v1")
        .chain_update(scope.statement()?)
        .chain_update(before_root)
        .chain_update((operations.len() as u16).to_be_bytes());
    for operation in operations {
        hash.update(operation);
    }
    Ok(hash.finalize().into())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationNoteFillBatch {
    pub version: u16,
    pub fills: Vec<ApplicationNoteFill>,
}

impl ApplicationNoteFillBatch {
    /// Shape and signed membership only. Each VM still validates every full
    /// certificate, monetary proof and cumulative reservation state.
    pub fn statement(&self) -> Result<[u8; 32], String> {
        if self.version != 1
            || self.fills.len() < 2
            || self.fills.len() > MAX_APPLICATION_BATCH_FILLS
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len()
                > MAX_APPLICATION_BATCH_BYTES
        {
            return Err("application fill batch is incomplete or oversized".into());
        }
        let first = &self.fills[0];
        let operations = self
            .fills
            .iter()
            .map(|fill| fill.operation_id)
            .collect::<Vec<_>>();
        let group = application_fill_group(&first.scope, first.before_root, &operations)?;
        let mut hash = Sha256::new()
            .chain_update(b"DEFMI:APPLICATION:FILL-BATCH:v1")
            .chain_update(group);
        for (index, fill) in self.fills.iter().enumerate() {
            if fill.scope != first.scope
                || fill.before_root != first.before_root
                || fill.batch
                    != Some(ApplicationFillBatchBinding {
                        group,
                        index: index as u16,
                        count: self.fills.len() as u16,
                    })
            {
                return Err(
                    "application fill batch omits, reorders or substitutes a signed member".into(),
                );
            }
            hash.update(fill.signing_message()?);
        }
        Ok(hash.finalize().into())
    }

    pub fn before_root(&self) -> Result<[u8; 32], String> {
        self.statement()?;
        Ok(self.fills[0].before_root)
    }
}
