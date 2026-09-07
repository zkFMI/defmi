use defmi_avalanche_vm::{
    application::NoApplications,
    block::Block,
    genesis::{CommitteeMember, Genesis},
    id::Id,
    recovery::{
        self, ApprovalWire, Checkpoint, CheckpointStatement, RecoveryPolicy, RecoveryTrust,
    },
    state::State,
    state_sync::{build_summary, StateSummary},
    transaction::TransactionEnvelope,
};
use defmi::{
    facility::{AssetDefinition, AssetKind, QuorumApproval, QuorumAuthorizer},
    governance::GovernanceSigner,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture {
    now: u64,
    state: State,
    summary: StateSummary,
    snapshot: Vec<u8>,
    archive: Vec<u8>,
    old_genesis: Genesis,
    current_genesis: Genesis,
    old: QuorumAuthorizer,
    current: QuorumAuthorizer,
    old_keys: BTreeMap<String, GovernanceSigner>,
    current_keys: BTreeMap<String, GovernanceSigner>,
    checkpoint: Checkpoint,
    policy: RecoveryPolicy,
    restore_approval: QuorumApproval,
    original: Vec<u8>,
}
fn committee(
    domain: &str,
    epoch: u64,
    start: u64,
    end: u64,
) -> (
    Genesis,
    QuorumAuthorizer,
    BTreeMap<String, GovernanceSigner>,
) {
    let keys: BTreeMap<_, _> = (0..3)
        .map(|i| {
            let node = format!("node-{i}");
            (
                node.clone(),
                GovernanceSigner::generate(&node, start, end).unwrap(),
            )
        })
        .collect();
    let genesis = Genesis {
        timestamp: start as i64,
        epoch,
        threshold: 2,
        members: keys
            .iter()
            .map(|(node, key)| CommitteeMember {
                node_id: node.clone(),
                key: key.verifying_key(),
            })
            .collect(),
    };
    let authority = genesis.authorizer(domain).unwrap();
    (genesis, authority, keys)
}
fn asset_transaction(
    state: &State,
    authority: &QuorumAuthorizer,
    keys: &BTreeMap<String, GovernanceSigner>,
    id: u8,
) -> Vec<u8> {
    let asset = AssetDefinition {
        asset_id: [id; 32],
        code: format!("ASSET{id}"),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: [id + 1; 32],
    };
    let approval = authority
        .approve(asset.statement().unwrap(), state.root(), keys)
        .unwrap();
    TransactionEnvelope::new("defmivm.issueAsset",json!({
        "asset":{"assetID":hex::encode(asset.asset_id),"code":asset.code,"kind":"cash","decimals":0,"termsDigest":hex::encode(asset.terms_digest)},
        "approval":ApprovalWire::from(&approval),"expectedBeforeRoot":hex::encode(state.root())
    })).unwrap().encode().unwrap()
}
impl Fixture {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let chain = Id([41; 32]);
        let (old_genesis, old, old_keys) = committee(&chain.to_string(), 1, now - 120, now - 30);
        let (current_genesis, current, current_keys) =
            committee(&chain.to_string(), 2, now - 20, now + 3600);
        let mut state = State::default();
        let original = asset_transaction(&state, &old, &old_keys, 10);
        state.apply(&original, &old, now - 60).unwrap();
        let block = Block {
            parent_id: Id([42; 32]),
            timestamp: (now - 60) as i64,
            height: 1,
            transactions: vec![original.clone()],
        };
        let (summary, snapshot) = build_summary(
            1337,
            chain,
            Id::digest(&old_genesis.encode().unwrap()),
            &block,
            &state,
        )
        .unwrap();
        let archive = original.clone();
        let statement =
            CheckpointStatement::prepare(&summary, &snapshot, &archive, now - 60, &NoApplications)
                .unwrap();
        let approval = old
            .approve(statement.digest().unwrap(), state.root(), &old_keys)
            .unwrap();
        let checkpoint = Checkpoint::seal(statement, approval, &old, now - 60).unwrap();
        let policy = RecoveryPolicy {
            version: 1,
            network_id: 1337,
            chain_id: chain.0,
            genesis_hash: summary.genesis_hash.0,
            expected_checkpoint: checkpoint.statement.digest().unwrap(),
            minimum_height: 1,
            target_id: [43; 32],
            nonce: [44; 32],
            not_before: now - 1,
            expires_at: now + 300,
        };
        let restore_approval = current
            .approve(policy.digest().unwrap(), state.root(), &current_keys)
            .unwrap();
        Self {
            now,
            state,
            summary,
            snapshot,
            archive,
            old_genesis,
            current_genesis,
            old,
            current,
            old_keys,
            current_keys,
            checkpoint,
            policy,
            restore_approval,
            original,
        }
    }
    fn trust(&self) -> RecoveryTrust<'_> {
        RecoveryTrust {
            policy: &self.policy,
            historical_authority: &self.old,
            current_authority: &self.current,
            recovery_approval: &self.restore_approval,
            now: self.now,
        }
    }
}

#[test]
fn expired_archival_keys_need_a_fresh_quorum_and_preserve_replay_state() {
    let f = Fixture::new();
    assert!(f
        .old_genesis
        .members
        .iter()
        .all(|m| m.key.valid_at(f.now).is_err()));
    let encoded = f.checkpoint.encode().unwrap();
    let checkpoint = Checkpoint::decode(&encoded).unwrap();
    let mut restored = recovery::restore(
        &checkpoint,
        &f.snapshot,
        &f.archive,
        &f.trust(),
        &NoApplications,
    )
    .unwrap()
    .state;
    assert_eq!(restored, f.state);
    let before = restored.root();
    assert!(restored.apply(&f.original, &f.current, f.now).is_err());
    assert_eq!(restored.root(), before);
    let retired_authorization = asset_transaction(&restored, &f.old, &f.old_keys, 12);
    assert!(restored
        .apply(&retired_authorization, &f.old, f.now)
        .is_err());
    assert_eq!(restored.root(), before);
    let next = asset_transaction(&restored, &f.current, &f.current_keys, 14);
    restored.apply(&next, &f.current, f.now).unwrap();
    assert_eq!(restored.transition_count, 2);

    let mut bad = checkpoint.clone();
    // Flip a fixed bit rather than relying on the original byte being nonzero.
    let mut sig = hex::decode(&checkpoint.approval.approvals[0].signature).unwrap();
    sig[0] ^= 1;
    bad.approval.approvals[0].signature = hex::encode(sig);
    assert!(recovery::restore(&bad, &f.snapshot, &f.archive, &f.trust(), &NoApplications).is_err());
    let mut classical = checkpoint.clone();
    for approval in &mut classical.approval.approvals {
        approval.signature.truncate(128);
    }
    assert!(recovery::restore(
        &classical,
        &f.snapshot,
        &f.archive,
        &f.trust(),
        &NoApplications
    )
    .is_err());
    let mut single = f.restore_approval.clone();
    single.approvals.truncate(1);
    let mut trust = f.trust();
    trust.recovery_approval = &single;
    assert!(recovery::restore(
        &checkpoint,
        &f.snapshot,
        &f.archive,
        &trust,
        &NoApplications
    )
    .is_err());
    let old_restore = f
        .old
        .approve(f.policy.digest().unwrap(), f.state.root(), &f.old_keys)
        .unwrap();
    let mut trust = f.trust();
    trust.current_authority = &f.old;
    trust.recovery_approval = &old_restore;
    assert!(recovery::restore(
        &checkpoint,
        &f.snapshot,
        &f.archive,
        &trust,
        &NoApplications
    )
    .is_err());
    let mut trust = f.trust();
    trust.now = f.policy.expires_at + 1;
    assert!(recovery::restore(
        &checkpoint,
        &f.snapshot,
        &f.archive,
        &trust,
        &NoApplications
    )
    .is_err());
    let mut policy = f.policy.clone();
    policy.minimum_height = 2;
    let mut trust = f.trust();
    trust.policy = &policy;
    assert!(recovery::restore(
        &checkpoint,
        &f.snapshot,
        &f.archive,
        &trust,
        &NoApplications
    )
    .is_err());
    let mut policy = f.policy.clone();
    policy.genesis_hash[0] ^= 1;
    let mut trust = f.trust();
    trust.policy = &policy;
    assert!(recovery::restore(
        &checkpoint,
        &f.snapshot,
        &f.archive,
        &trust,
        &NoApplications
    )
    .is_err());
    let mut policy = f.policy.clone();
    policy.nonce[0] ^= 1;
    let mut trust = f.trust();
    trust.policy = &policy;
    assert!(recovery::restore(
        &checkpoint,
        &f.snapshot,
        &f.archive,
        &trust,
        &NoApplications
    )
    .is_err());
    let mut snapshot = f.snapshot.clone();
    snapshot[30] ^= 1;
    assert!(recovery::restore(
        &checkpoint,
        &snapshot,
        &f.archive,
        &f.trust(),
        &NoApplications
    )
    .is_err());
    assert!(recovery::restore(
        &checkpoint,
        &f.snapshot,
        b"another archive",
        &f.trust(),
        &NoApplications
    )
    .is_err());
    let mut trailing = encoded;
    trailing.push(b' ');
    assert!(Checkpoint::decode(&trailing).is_err());
    let mut unknown = checkpoint.clone();
    unknown.statement.version = 2;
    assert!(unknown.encode().is_err());
    let mut application_state = f.state.clone();
    application_state
        .application_states
        .insert("unknown-application".into(), vec![1]);
    let block = defmi_avalanche_vm::state_sync::decode_snapshot(&f.summary, &f.snapshot)
        .unwrap()
        .block;
    let (summary, snapshot) = build_summary(
        f.summary.network_id,
        f.summary.chain_id,
        f.summary.genesis_hash,
        &block,
        &application_state,
    )
    .unwrap();
    assert!(
        CheckpointStatement::prepare(&summary, &snapshot, &f.archive, f.now, &NoApplications)
            .is_err()
    );
}

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn recovery_cli_prepares_seals_and_restores_a_real_vm_snapshot_without_overwrite() {
    let f = Fixture::new();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".artifacts")
        .join(format!("recovery-{}-{unique}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    let directory = Directory(path);
    let write = |name: &str, bytes: &[u8]| fs::write(directory.0.join(name), bytes).unwrap();
    write("summary.bin", &f.summary.encode().unwrap());
    write("snapshot.bin", &f.snapshot);
    write("archive.bin", &f.archive);
    write("committee.bin", &f.current_genesis.encode().unwrap());
    let run = |mode: &str, options: &[(&str, &str)]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_qomm-avalanche-vm"));
        command.args(["recovery", mode]);
        for (key, value) in options {
            command.arg(key).arg(directory.0.join(value));
        }
        command.output().unwrap()
    };
    let prepare = run(
        "prepare",
        &[
            ("--summary", "summary.bin"),
            ("--snapshot", "snapshot.bin"),
            ("--archive", "archive.bin"),
            ("--out", "statement.json"),
        ],
    );
    assert!(
        prepare.status.success(),
        "{}",
        String::from_utf8_lossy(&prepare.stderr)
    );
    let statement: CheckpointStatement =
        serde_json::from_slice(&fs::read(directory.0.join("statement.json")).unwrap()).unwrap();
    let approval = f
        .current
        .approve(statement.digest().unwrap(), f.state.root(), &f.current_keys)
        .unwrap();
    write(
        "seal-approval.json",
        &serde_json::to_vec(&ApprovalWire::from(&approval)).unwrap(),
    );
    let sealed = run(
        "seal",
        &[
            ("--statement", "statement.json"),
            ("--approval", "seal-approval.json"),
            ("--committee", "committee.bin"),
            ("--out", "checkpoint.json"),
        ],
    );
    assert!(
        sealed.status.success(),
        "{}",
        String::from_utf8_lossy(&sealed.stderr)
    );
    let checkpoint =
        Checkpoint::decode(&fs::read(directory.0.join("checkpoint.json")).unwrap()).unwrap();
    let mut policy = f.policy.clone();
    policy.expected_checkpoint = checkpoint.statement.digest().unwrap();
    write("policy.json", &serde_json::to_vec(&policy).unwrap());
    let request = run(
        "request",
        &[
            ("--checkpoint", "checkpoint.json"),
            ("--policy", "policy.json"),
            ("--out", "request.json"),
        ],
    );
    assert!(request.status.success());
    let request: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.0.join("request.json")).unwrap()).unwrap();
    assert_eq!(request["statement"], hex::encode(policy.digest().unwrap()));
    let approval = f
        .current
        .approve(policy.digest().unwrap(), f.state.root(), &f.current_keys)
        .unwrap();
    write(
        "restore-approval.json",
        &serde_json::to_vec(&ApprovalWire::from(&approval)).unwrap(),
    );
    let options = [
        ("--checkpoint", "checkpoint.json"),
        ("--snapshot", "snapshot.bin"),
        ("--archive", "archive.bin"),
        ("--policy", "policy.json"),
        ("--historical-committee", "committee.bin"),
        ("--current-committee", "committee.bin"),
        ("--approval", "restore-approval.json"),
        ("--out-dir", "restored"),
    ];
    let restored = run("restore", &options);
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let state_bytes = fs::read(directory.0.join("restored/state.json")).unwrap();
    let mut state = State::decode(&state_bytes).unwrap();
    assert_eq!(state, f.state);
    assert_eq!(
        Block::decode(&fs::read(directory.0.join("restored/block.bin")).unwrap())
            .unwrap()
            .id()
            .unwrap(),
        f.summary.block_id
    );
    assert!(!run("restore", &options).status.success());
    assert_eq!(
        fs::read(directory.0.join("restored/state.json")).unwrap(),
        state_bytes
    );
    assert!(state.apply(&f.original, &f.current, f.now).is_err());
    let next = asset_transaction(&state, &f.current, &f.current_keys, 16);
    state.apply(&next, &f.current, f.now).unwrap();
    assert_eq!(state.transition_count, 2);
}
