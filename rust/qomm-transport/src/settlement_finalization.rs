//! Private DeFMI execution contexts supplied after Maker/Taker reservations.
//!
//! The MPC output is already fixed when this file is created. Proof nodes use
//! it only to bind that output to reservation receipts and the current DeFMI
//! state root; it contains no amount, price, inventory, or commitment opening.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use qomm_zkpi::typed::ExecutionContext;
use qomm_zkpi::typed_wire;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::settlement_handoff::SettlementHandoffBundle;

const VERSION: u8 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    job_id: String,
    context: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireBundle {
    version: u8,
    private_finalization: bool,
    records: Vec<WireRecord>,
}

fn validate_population(
    handoff: &SettlementHandoffBundle,
    contexts: &BTreeMap<[u8; 32], ExecutionContext>,
) -> Result<(), String> {
    let jobs = handoff
        .records
        .iter()
        .map(|record| record.job_id)
        .collect::<BTreeSet<_>>();
    let supplied = contexts.keys().copied().collect::<BTreeSet<_>>();
    if jobs.is_empty() || jobs.len() > 4096 || jobs != supplied {
        return Err("finalization contexts do not exactly cover the handoff jobs".into());
    }
    for record in &handoff.records {
        contexts[&record.job_id]
            .validate_against(&record.instruction)
            .map_err(str::to_string)?;
    }
    Ok(())
}

pub fn write_private(
    path: impl AsRef<Path>,
    handoff: &SettlementHandoffBundle,
    contexts: &BTreeMap<[u8; 32], ExecutionContext>,
) -> Result<(), String> {
    validate_population(handoff, contexts)?;
    let wire = WireBundle {
        version: VERSION,
        private_finalization: true,
        records: handoff
            .records
            .iter()
            .map(|record| WireRecord {
                job_id: hex::encode(record.job_id),
                context: BASE64.encode(typed_wire::encode_context(&contexts[&record.job_id])),
            })
            .collect(),
    };
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(&wire).map_err(|error| error.to_string())?;
    let temporary: PathBuf = parent.join(format!(
        ".qomm-settlement-finalization-{}.tmp",
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn read_private(
    path: impl AsRef<Path>,
    handoff: &SettlementHandoffBundle,
) -> Result<BTreeMap<[u8; 32], ExecutionContext>, String> {
    let path = path.as_ref();
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > 8 << 20
    {
        return Err("settlement finalization must be a bounded private regular file".into());
    }
    let wire: WireBundle =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("settlement finalization JSON is invalid: {error}"))?;
    if wire.version != VERSION
        || !wire.private_finalization
        || wire.records.is_empty()
        || wire.records.len() > 4096
    {
        return Err("settlement finalization header is invalid".into());
    }
    let payments = handoff
        .records
        .iter()
        .map(|record| (record.job_id, &record.instruction))
        .collect::<BTreeMap<_, _>>();
    let mut contexts = BTreeMap::new();
    for record in wire.records {
        let job_id: [u8; 32] = hex::decode(&record.job_id)
            .map_err(|_| "finalization job id is malformed".to_string())?
            .try_into()
            .map_err(|_| "finalization job id is malformed".to_string())?;
        let payment = payments
            .get(&job_id)
            .ok_or_else(|| "finalization names a job outside the handoff".to_string())?;
        let context = typed_wire::decode_context(
            &BASE64
                .decode(&record.context)
                .map_err(|_| "finalization context is not valid base64".to_string())?,
            payment,
        )
        .map_err(|_| "finalization context wire is invalid".to_string())?;
        if contexts.insert(job_id, context).is_some() {
            return Err("finalization repeats one proof job".into());
        }
    }
    validate_population(handoff, &contexts)?;
    Ok(contexts)
}
