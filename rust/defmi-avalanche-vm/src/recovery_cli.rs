use defmi_avalanche_vm::{
    application::NoApplications,
    genesis::{Genesis, MAX_GENESIS_BYTES},
    id::Id,
    recovery::{
        self, ApprovalWire, Checkpoint, CheckpointStatement, RecoveryPolicy, RecoveryTrust,
        MAX_ARCHIVE_BYTES, MAX_CHECKPOINT_BYTES,
    },
    state_sync::{StateSummary, MAX_SNAPSHOT_BYTES},
};
use serde::de::DeserializeOwned;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err("recovery input is not a bounded regular file".into());
    }
    let mut out = Vec::new();
    fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|error| error.to_string())?;
    if out.len() != metadata.len() as usize {
        return Err("recovery input changed during read".into());
    }
    Ok(out)
}
fn json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&read(path, MAX_CHECKPOINT_BYTES)?).map_err(|error| error.to_string())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|error| error.to_string())
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    let mode = arguments
        .first()
        .ok_or("expected recovery prepare|seal|request|restore")?;
    let allowed: &[&str] = match mode.as_str() {
        "prepare" => &["--summary", "--snapshot", "--archive", "--out"],
        "seal" => &["--statement", "--approval", "--committee", "--out"],
        "request" => &["--checkpoint", "--policy", "--out"],
        "restore" => &[
            "--checkpoint",
            "--snapshot",
            "--archive",
            "--policy",
            "--historical-committee",
            "--current-committee",
            "--approval",
            "--out-dir",
        ],
        _ => return Err("unknown recovery operation".into()),
    };
    let mut options = BTreeMap::new();
    let mut pairs = arguments[1..].chunks_exact(2);
    for pair in &mut pairs {
        if !allowed.contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("unknown or duplicate recovery option".into());
        }
    }
    if !pairs.remainder().is_empty() || options.len() != allowed.len() {
        return Err("missing recovery option or value".into());
    }
    let file = |name: &str| -> Result<PathBuf, String> {
        options
            .get(name)
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing {name}"))
    };
    match mode.as_str() {
        "prepare" => {
            let summary = StateSummary::decode(&read(&file("--summary")?, 2048)?)?;
            let statement = CheckpointStatement::prepare(
                &summary,
                &read(&file("--snapshot")?, MAX_SNAPSHOT_BYTES)?,
                &read(&file("--archive")?, MAX_ARCHIVE_BYTES)?,
                now()?,
                &NoApplications,
            )?;
            let bytes = serde_json::to_vec(&statement).map_err(|error| error.to_string())?;
            write_new(&file("--out")?, &bytes)?;
            println!(
                "{}",
                serde_json::json!({"statement":hex::encode(statement.digest()?),"beforeRoot":hex::encode(summary.state_root)})
            );
        }
        "seal" => {
            let statement: CheckpointStatement = json(&file("--statement")?)?;
            let summary = statement.validate()?;
            let genesis = Genesis::decode(&read(&file("--committee")?, MAX_GENESIS_BYTES)?)?;
            let authority = genesis.authorizer(&summary.chain_id.to_string())?;
            let approval: ApprovalWire = json(&file("--approval")?)?;
            let checkpoint = Checkpoint::seal(statement, approval.approval()?, &authority, now()?)?;
            write_new(&file("--out")?, &checkpoint.encode()?)?;
            println!(
                "{}",
                serde_json::json!({"checkpoint":hex::encode(checkpoint.statement.digest()?),"historical_authenticity":"unchanged"})
            );
        }
        "request" => {
            let checkpoint =
                Checkpoint::decode(&read(&file("--checkpoint")?, MAX_CHECKPOINT_BYTES)?)?;
            let policy: RecoveryPolicy = json(&file("--policy")?)?;
            let summary = checkpoint.statement.validate()?;
            if checkpoint.statement.digest()? != policy.expected_checkpoint
                || !summary.matches_chain(
                    policy.network_id,
                    Id(policy.chain_id),
                    Id(policy.genesis_hash),
                )
                || summary.height < policy.minimum_height
            {
                return Err(
                    "checkpoint does not match independently pinned recovery policy".into(),
                );
            }
            let value = serde_json::json!({"statement":hex::encode(policy.digest()?),"beforeRoot":hex::encode(summary.state_root)});
            write_new(
                &file("--out")?,
                &serde_json::to_vec(&value).map_err(|error| error.to_string())?,
            )?;
        }
        "restore" => {
            let checkpoint =
                Checkpoint::decode(&read(&file("--checkpoint")?, MAX_CHECKPOINT_BYTES)?)?;
            let policy: RecoveryPolicy = json(&file("--policy")?)?;
            let summary = checkpoint.statement.validate()?;
            let domain = Id(policy.chain_id).to_string();
            let historical =
                Genesis::decode(&read(&file("--historical-committee")?, MAX_GENESIS_BYTES)?)?
                    .authorizer(&domain)?;
            let current =
                Genesis::decode(&read(&file("--current-committee")?, MAX_GENESIS_BYTES)?)?
                    .authorizer(&domain)?;
            let approval: ApprovalWire = json(&file("--approval")?)?;
            let approval = approval.approval()?;
            let trust = RecoveryTrust {
                policy: &policy,
                historical_authority: &historical,
                current_authority: &current,
                recovery_approval: &approval,
                now: now()?,
            };
            let decoded = recovery::restore(
                &checkpoint,
                &read(&file("--snapshot")?, MAX_SNAPSHOT_BYTES)?,
                &read(&file("--archive")?, MAX_ARCHIVE_BYTES)?,
                &trust,
                &NoApplications,
            )?;
            // An existing validator directory is never overwritten. The signed
            // restore produces an offline handoff, not an implicit live cutover.
            let directory = file("--out-dir")?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|error| error.to_string())?;
            write_new(&directory.join("state.json"), &decoded.state.encode()?)?;
            write_new(&directory.join("block.bin"), &decoded.block_bytes)?;
            write_new(&directory.join("summary.bin"), &summary.encode()?)?;
            let report = serde_json::json!({"version":1,"checkpoint":hex::encode(policy.expected_checkpoint),
                "state_root":hex::encode(decoded.state.root()),"block_id":hex::encode(summary.block_id.0),
                "height":summary.height,"target_id":hex::encode(policy.target_id),"nonce":hex::encode(policy.nonce),
                "historical_authenticity":"unchanged","live_activation":false});
            write_new(
                &directory.join("restored.json"),
                &serde_json::to_vec(&report).map_err(|error| error.to_string())?,
            )?;
            fs::File::open(&directory)
                .and_then(|file| file.sync_all())
                .map_err(|error| error.to_string())?;
            println!("{report}");
        }
        _ => unreachable!(),
    }
    Ok(())
}
