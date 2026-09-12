//! Real-proof canonical-state acceptance harness for the opt-in CoCode trial.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use defmi::{
    avalanche::{AcceptedTransition, AvalancheClient, AvalancheRpcClient},
    facility::{QuorumApproval, QuorumAuthorizer},
    governance::{public_development_keys, public_development_keys_for_policy, GovernanceSigner},
};
use defmi_avalanche_vm::{
    block::{Block, MAX_BLOCK_BYTES, MAX_TRANSACTION_BYTES},
    id::Id,
    research_cocode::{
        approval_json, encode_begin_transaction, encode_book_transaction, encode_chunk_transaction,
        encode_commit_transaction, encode_policy_transaction, AccountAssetHandle, CommitRequest,
        DeploymentPolicy, ProofChunkUpload, ProofManifest, ResearchBookGenesis, SettlementReceipt,
        DEPLOYMENT_MODE, MAX_PROOF_BYTES, PROOF_CHUNK_BYTES, PROOF_PROTOCOL,
        QUERY_AGREEMENT_PROOF_PROTOCOL,
    },
    state::{State, TransitionReceipt},
    state_sync::{build_summary, decode_snapshot, StateSummary},
    transaction::TransactionEnvelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zkfmi_cosnark_trial::integration::SettlementStatement;
use zkfmi_crypto::mode::{DeploymentCryptoPolicy, PqcMode};

const NETWORK_ID: u32 = 999_901;
const FIRST_TIMESTAMP: u64 = 1_788_865_472;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveConfig {
    chain_id: String,
    node_uris: Vec<String>,
    #[serde(default = "default_live_timeout_seconds")]
    acceptance_timeout_seconds: u64,
    #[serde(default = "default_live_poll_millis")]
    poll_interval_millis: u64,
    restart: LiveRestartConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveRestartConfig {
    runner_path: PathBuf,
    runner_endpoint: String,
    node_name: String,
    plugin_dir: Option<PathBuf>,
    #[serde(default = "default_live_timeout_seconds")]
    timeout_seconds: u64,
}

fn default_live_timeout_seconds() -> u64 {
    180
}

fn default_live_poll_millis() -> u64 {
    200
}

impl LiveConfig {
    fn validate(&self) -> Result<(), String> {
        if self.chain_id.is_empty()
            || self.node_uris.len() != 5
            || self.acceptance_timeout_seconds == 0
            || self.poll_interval_millis == 0
            || self.restart.timeout_seconds == 0
            || self.restart.runner_endpoint.is_empty()
            || self.restart.node_name.is_empty()
            || self.restart.runner_path.as_os_str().is_empty()
        {
            return Err("live config requires a chain, exactly five nodes, positive timeouts, and a complete restart command".into());
        }
        let mut normalized = BTreeSet::new();
        for uri in &self.node_uris {
            let uri = uri.trim_end_matches('/');
            if uri.is_empty() || uri.contains("/ext/bc/") || !normalized.insert(uri.to_string()) {
                return Err(
                    "live nodeUris must contain five distinct AvalancheGo base URIs".into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct LiveTransitionEvidence {
    method: String,
    tx_id: String,
    block_id: String,
    accepted_height: u64,
    statement: String,
    before_root: String,
    after_root: String,
    validator_receipt_count: usize,
    validator_roots: Vec<String>,
}

#[derive(Serialize)]
struct LiveNegativeEvidence {
    gate: String,
    method: String,
    tx_id: String,
    outcome: &'static str,
    prior_accepted_transition: bool,
    observed_node_statuses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejection_reason: Option<String>,
    roots_before: Vec<String>,
    roots_after: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LiveMetadata {
    network_id: u64,
    genesis_timestamp: i64,
    committee_epoch: u64,
    committee_threshold: usize,
    committee_members: usize,
    deployment_crypto_policy: Option<DeploymentCryptoPolicy>,
}

#[derive(Serialize)]
struct LiveRestartEvidence {
    node_name: String,
    elapsed_millis: u128,
    root_recovered: bool,
}

#[derive(Serialize)]
struct PendingUploadRestartEvidence {
    accepted: bool,
    node_name: String,
    state_bytes: usize,
    proof_uploaded_chunks: usize,
    proof_expected_chunks: u32,
    roots_before_restart: Vec<String>,
    roots_after_restart: Vec<String>,
    elapsed_millis: u128,
}

#[derive(Serialize)]
struct LiveNetworkEvidence {
    accepted: bool,
    node_count: usize,
    chain_id: String,
    network_id: u64,
    genesis_verified: bool,
    genesis_timestamp: i64,
    genesis_committee_epoch: u64,
    genesis_committee_threshold: usize,
    genesis_committee_members: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    deployment_crypto_policy: Option<DeploymentCryptoPolicy>,
    initial_roots: Vec<String>,
    accepted_transitions: Vec<LiveTransitionEvidence>,
    negative_transactions: Vec<LiveNegativeEvidence>,
    roots_before_restart: Vec<String>,
    roots_after_restart: Vec<String>,
    pending_upload_restart: PendingUploadRestartEvidence,
    restart: LiveRestartEvidence,
    last_accepted_block_ids: Vec<String>,
    environment: &'static str,
}

struct LiveNetwork {
    config: LiveConfig,
    clients: Vec<AvalancheRpcClient>,
    timeout: Duration,
    poll_interval: Duration,
    metadata: LiveMetadata,
    initial_roots: Vec<String>,
    transitions: Vec<LiveTransitionEvidence>,
    negatives: Vec<LiveNegativeEvidence>,
    pending_upload_restart: Option<PendingUploadRestartEvidence>,
}

struct Harness {
    state: State,
    authorizer: QuorumAuthorizer,
    signers: BTreeMap<String, GovernanceSigner>,
    parent_id: Id,
    height: u64,
    timestamp: u64,
    last_block: Option<Block>,
    live: Option<LiveNetwork>,
}

impl Harness {
    fn new(
        live_config: Option<&LiveConfig>,
        deployment_crypto_policy: Option<&DeploymentCryptoPolicy>,
    ) -> Result<Self, String> {
        let all_signers = match deployment_crypto_policy {
            Some(policy) => public_development_keys_for_policy(policy)?,
            None => public_development_keys()?,
        };
        let state = State {
            deployment_crypto_policy: deployment_crypto_policy.cloned(),
            ..State::default()
        };
        let (authorizer, signers, live) = match live_config {
            Some(config) => {
                let live = LiveNetwork::connect(
                    config,
                    state.root(),
                    &all_signers,
                    deployment_crypto_policy,
                )?;
                let authorizer = deployment_authorizer(
                    all_signers
                        .iter()
                        .map(|(node, signer)| (node.clone(), signer.verifying_key()))
                        .collect(),
                    live.metadata.committee_threshold,
                    live.metadata.committee_epoch,
                    config.chain_id.clone(),
                    deployment_crypto_policy,
                )?;
                let signers = all_signers
                    .into_iter()
                    .take(live.metadata.committee_threshold)
                    .collect();
                (authorizer, signers, Some(live))
            }
            None => {
                let authorizer = deployment_authorizer(
                    all_signers
                        .iter()
                        .map(|(node, signer)| (node.clone(), signer.verifying_key()))
                        .collect(),
                    2,
                    1,
                    "cocode-canonical-acceptance",
                    deployment_crypto_policy,
                )?;
                let signers = all_signers.into_iter().take(2).collect();
                (authorizer, signers, None)
            }
        };
        Ok(Self {
            state,
            authorizer,
            signers,
            parent_id: Id::digest(b"cocode-canonical-acceptance-genesis-v1"),
            height: 0,
            timestamp: FIRST_TIMESTAMP,
            last_block: None,
            live,
        })
    }

    fn approval(&self, statement: [u8; 32]) -> Result<QuorumApproval, String> {
        self.authorizer
            .approve(statement, self.state.root(), &self.signers)
    }

    fn canonical_block(&self, transaction: &[u8]) -> Result<Block, String> {
        if transaction.len() > MAX_TRANSACTION_BYTES {
            return Err("acceptance transaction exceeds the unchanged one-MiB limit".into());
        }
        let envelope = TransactionEnvelope::decode(transaction)?;
        if envelope.encode()? != transaction {
            return Err("acceptance transaction failed canonical roundtrip".into());
        }
        let block = Block {
            parent_id: self.parent_id,
            timestamp: self.timestamp as i64,
            height: self.height + 1,
            transactions: vec![transaction.to_vec()],
        };
        let encoded = block.encode()?;
        if encoded.len() > MAX_BLOCK_BYTES {
            return Err("acceptance block exceeds the unchanged 1.5-MiB limit".into());
        }
        let decoded = Block::decode(&encoded)?;
        if decoded.encode()? != encoded {
            return Err("acceptance block failed canonical roundtrip".into());
        }
        Ok(decoded)
    }

    fn apply(&mut self, transaction: Vec<u8>) -> Result<TransitionReceipt, String> {
        let block = self.canonical_block(&transaction)?;
        let mut candidate = self.state.clone();
        let receipt = candidate.apply(&block.transactions[0], &self.authorizer, self.timestamp)?;
        candidate.validate()?;
        if let Some(live) = self.live.as_mut() {
            live.accept(&transaction, &receipt)?;
        }
        self.state = candidate;
        self.parent_id = block.id()?;
        self.height = block.height;
        self.timestamp = self
            .timestamp
            .checked_add(1)
            .ok_or_else(|| "acceptance timestamp overflow".to_string())?;
        self.last_block = Some(block);
        Ok(receipt)
    }

    fn rejects(&mut self, gate: &str, transaction: &[u8]) -> Result<bool, String> {
        let block = self.canonical_block(transaction)?;
        let mut candidate = self.state.clone();
        if candidate
            .apply(&block.transactions[0], &self.authorizer, self.timestamp)
            .is_ok()
            || candidate != self.state
        {
            return Ok(false);
        }
        if let Some(live) = self.live.as_mut() {
            live.reject(gate, transaction, self.state.root())?;
        }
        Ok(true)
    }
}

fn deployment_authorizer(
    nodes: BTreeMap<String, zkfmi_crypto::key::KeyRecord>,
    threshold: usize,
    epoch: u64,
    domain: impl Into<String>,
    deployment_crypto_policy: Option<&DeploymentCryptoPolicy>,
) -> Result<QuorumAuthorizer, String> {
    match deployment_crypto_policy {
        Some(policy) => {
            QuorumAuthorizer::new_for_deployment(nodes, threshold, epoch, domain, policy.clone())
        }
        None => QuorumAuthorizer::new(nodes, threshold, epoch, domain),
    }
}

impl LiveNetwork {
    fn connect(
        config: &LiveConfig,
        expected_initial_root: [u8; 32],
        all_signers: &BTreeMap<String, GovernanceSigner>,
        deployment_crypto_policy: Option<&DeploymentCryptoPolicy>,
    ) -> Result<Self, String> {
        config.validate()?;
        let clients = live_clients(config)?;
        let metadata = verify_live_metadata(
            &clients,
            &config.chain_id,
            all_signers,
            deployment_crypto_policy,
        )?;
        let initial_roots = expected_root_strings(&clients, expected_initial_root)?;
        Ok(Self {
            config: config.clone(),
            clients,
            timeout: Duration::from_secs(config.acceptance_timeout_seconds),
            poll_interval: Duration::from_millis(config.poll_interval_millis),
            metadata,
            initial_roots,
            transitions: Vec::new(),
            negatives: Vec::new(),
            pending_upload_restart: None,
        })
    }

    fn accept(&mut self, transaction: &[u8], expected: &TransitionReceipt) -> Result<(), String> {
        let envelope = TransactionEnvelope::decode(transaction)?;
        let result = self.clients[0].call(&envelope.method, envelope.params.clone())?;
        let tx_id = transaction_id(&result)?;
        let expected_tx_id = expected.transaction_id.to_string();
        if tx_id != expected_tx_id {
            return Err("Avalanche RPC returned a different transaction identifier".into());
        }
        let receipts = self
            .clients
            .iter()
            .map(|client| client.wait_accepted(&tx_id, self.timeout, self.poll_interval))
            .collect::<Result<Vec<_>, _>>()?;
        let accepted = receipts
            .first()
            .ok_or_else(|| "live acceptance has no validator receipt".to_string())?;
        if receipts.iter().any(|receipt| receipt != accepted)
            || accepted.tx_id != expected_tx_id
            || accepted.statement != expected.statement
            || accepted.before_root != expected.before_root
            || accepted.after_root != expected.after_root
        {
            return Err(
                "five-validator receipt differs from the canonical local transition".into(),
            );
        }
        let validator_roots = expected_root_strings(&self.clients, expected.after_root)?;
        self.transitions.push(LiveTransitionEvidence {
            method: envelope.method,
            tx_id: accepted.tx_id.clone(),
            block_id: accepted.block_id.clone(),
            accepted_height: accepted.height,
            statement: hex::encode(accepted.statement),
            before_root: hex::encode(accepted.before_root),
            after_root: hex::encode(accepted.after_root),
            validator_receipt_count: receipts.len(),
            validator_roots,
        });
        Ok(())
    }

    fn reject(
        &mut self,
        gate: &str,
        transaction: &[u8],
        expected_root: [u8; 32],
    ) -> Result<(), String> {
        let roots_before = expected_root_strings(&self.clients, expected_root)?;
        let envelope = TransactionEnvelope::decode(transaction)?;
        let expected_tx_id = envelope.id()?.to_string();
        let result = self.clients[0].call(&envelope.method, envelope.params.clone())?;
        let tx_id = transaction_id(&result)?;
        if tx_id != expected_tx_id {
            return Err(
                "Avalanche negative RPC returned a different transaction identifier".into(),
            );
        }
        let prior = self
            .transitions
            .iter()
            .find(|transition| transition.tx_id == tx_id)
            .map(|transition| {
                (
                    transition.block_id.clone(),
                    transition.accepted_height,
                    transition.statement.clone(),
                    transition.before_root.clone(),
                    transition.after_root.clone(),
                )
            });
        let started = Instant::now();
        loop {
            let observations = self
                .clients
                .iter()
                .map(|client| client.call("defmivm.txStatus", json!({"txID": tx_id})))
                .collect::<Result<Vec<_>, _>>()?;
            let statuses = observations
                .iter()
                .map(|observation| {
                    observation
                        .get("status")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| "live negative status is malformed".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if statuses.iter().any(|status| {
                !matches!(
                    status.as_str(),
                    "accepted" | "rejected" | "pending" | "processing" | "unknown"
                )
            }) {
                return Err("live negative returned an unknown transaction status".into());
            }
            let accepted_count = statuses
                .iter()
                .filter(|status| status.as_str() == "accepted")
                .count();
            let rejected_count = statuses
                .iter()
                .filter(|status| status.as_str() == "rejected")
                .count();
            if accepted_count != 0 && rejected_count != 0 {
                return Err(
                    "validators disagree whether the negative transaction was accepted".into(),
                );
            }
            if accepted_count != 0 {
                let Some((block_id, height, statement, before_root, after_root)) = prior.as_ref()
                else {
                    return Err(format!("live negative gate {gate} was accepted"));
                };
                if accepted_count == self.clients.len() {
                    let receipts = observations
                        .iter()
                        .map(AcceptedTransition::parse)
                        .collect::<Result<Vec<_>, _>>()?;
                    let first = receipts
                        .first()
                        .ok_or_else(|| "idempotent replay has no receipt".to_string())?;
                    if receipts.iter().any(|receipt| receipt != first)
                        || &first.block_id != block_id
                        || first.height != *height
                        || hex::encode(first.statement) != *statement
                        || hex::encode(first.before_root) != *before_root
                        || hex::encode(first.after_root) != *after_root
                    {
                        return Err(
                            "idempotent replay receipt differs from its prior acceptance".into(),
                        );
                    }
                    let roots_after = expected_root_strings(&self.clients, expected_root)?;
                    self.negatives.push(LiveNegativeEvidence {
                        gate: gate.to_string(),
                        method: envelope.method,
                        tx_id,
                        outcome: "accepted_idempotent_replay",
                        prior_accepted_transition: true,
                        observed_node_statuses: statuses,
                        rejection_reason: None,
                        roots_before,
                        roots_after,
                    });
                    return Ok(());
                }
            } else if rejected_count != 0 {
                if prior.is_some() {
                    return Err(
                        "a previously accepted transaction was later reported rejected".into(),
                    );
                }
                let rejection_reason = observations.iter().find_map(|observation| {
                    (observation.get("status").and_then(Value::as_str) == Some("rejected")).then(
                        || {
                            observation
                                .get("reason")
                                .and_then(Value::as_str)
                                .unwrap_or("unspecified")
                                .to_string()
                        },
                    )
                });
                let roots_after = expected_root_strings(&self.clients, expected_root)?;
                self.negatives.push(LiveNegativeEvidence {
                    gate: gate.to_string(),
                    method: envelope.method,
                    tx_id,
                    outcome: "explicitly_rejected",
                    prior_accepted_transition: false,
                    observed_node_statuses: statuses,
                    rejection_reason,
                    roots_before,
                    roots_after,
                });
                return Ok(());
            }
            if started.elapsed() >= self.timeout {
                return Err(format!(
                    "live negative gate {gate} did not reach an explicit terminal status"
                ));
            }
            thread::sleep(self.poll_interval);
        }
    }

    fn restart_pending_upload(
        &mut self,
        expected_root: [u8; 32],
        state_bytes: usize,
        proof_uploaded_chunks: usize,
        proof_expected_chunks: u32,
    ) -> Result<(), String> {
        if self.pending_upload_restart.is_some() {
            return Err("pending-upload validator restart was already recorded".into());
        }
        if self.config.restart.node_name != "node3" {
            return Err("pending-upload recovery must restart node3".into());
        }
        if state_bytes <= avalanche_rpcchainvm_qomm::DEFAULT_MAX_MESSAGE_BYTES {
            return Err(
                "pending-upload restart state does not cross the 64 MiB rpcdb bound".into(),
            );
        }
        if usize::try_from(proof_expected_chunks).ok() != Some(proof_uploaded_chunks) {
            return Err("pending-upload restart requires the complete proof upload".into());
        }
        let roots_before_restart = expected_root_strings(&self.clients, expected_root)?;
        let elapsed_millis = restart_network(&self.config.restart)?;
        self.clients = live_clients(&self.config)?;
        let roots_after_restart = wait_for_expected_roots(
            &self.clients,
            expected_root,
            Duration::from_secs(self.config.restart.timeout_seconds),
            self.poll_interval,
        )?;
        let all_signers = development_keys(self.metadata.deployment_crypto_policy.as_ref())?;
        let recovered_metadata = verify_live_metadata(
            &self.clients,
            &self.config.chain_id,
            &all_signers,
            self.metadata.deployment_crypto_policy.as_ref(),
        )?;
        if recovered_metadata != self.metadata {
            return Err("Avalanche network metadata changed across pending-upload restart".into());
        }
        if roots_before_restart.len() != 5 || roots_after_restart.len() != 5 {
            return Err("pending-upload restart did not verify all five validators".into());
        }
        self.pending_upload_restart = Some(PendingUploadRestartEvidence {
            accepted: true,
            node_name: self.config.restart.node_name.clone(),
            state_bytes,
            proof_uploaded_chunks,
            proof_expected_chunks,
            roots_before_restart,
            roots_after_restart,
            elapsed_millis,
        });
        Ok(())
    }

    fn finish(mut self, final_root: [u8; 32]) -> Result<LiveNetworkEvidence, String> {
        let pending_upload_restart = self
            .pending_upload_restart
            .take()
            .ok_or_else(|| "live run omitted the pending-upload validator restart".to_string())?;
        let roots_before_restart = expected_root_strings(&self.clients, final_root)?;
        let elapsed_millis = restart_network(&self.config.restart)?;
        self.clients = live_clients(&self.config)?;
        let roots_after_restart = wait_for_expected_roots(
            &self.clients,
            final_root,
            Duration::from_secs(self.config.restart.timeout_seconds),
            self.poll_interval,
        )?;
        let all_signers = development_keys(self.metadata.deployment_crypto_policy.as_ref())?;
        let recovered_metadata = verify_live_metadata(
            &self.clients,
            &self.config.chain_id,
            &all_signers,
            self.metadata.deployment_crypto_policy.as_ref(),
        )?;
        if recovered_metadata != self.metadata {
            return Err("Avalanche network metadata changed across validator restart".into());
        }
        let last_accepted_block_ids = self
            .clients
            .iter()
            .map(|client| {
                let result = client.call("defmivm.lastAccepted", json!({}))?;
                result
                    .get("blockID")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| "lastAccepted response has no blockID".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if last_accepted_block_ids.is_empty()
            || last_accepted_block_ids
                .windows(2)
                .any(|ids| ids[0] != ids[1])
        {
            return Err("validators disagree on the last accepted block after restart".into());
        }
        let node_count = self.clients.len();
        Ok(LiveNetworkEvidence {
            accepted: true,
            node_count,
            chain_id: self.config.chain_id.clone(),
            network_id: self.metadata.network_id,
            genesis_verified: true,
            genesis_timestamp: self.metadata.genesis_timestamp,
            genesis_committee_epoch: self.metadata.committee_epoch,
            genesis_committee_threshold: self.metadata.committee_threshold,
            genesis_committee_members: self.metadata.committee_members,
            deployment_crypto_policy: self.metadata.deployment_crypto_policy.clone(),
            initial_roots: self.initial_roots,
            accepted_transitions: self.transitions,
            negative_transactions: self.negatives,
            roots_before_restart,
            roots_after_restart,
            pending_upload_restart,
            restart: LiveRestartEvidence {
                node_name: self.config.restart.node_name.clone(),
                elapsed_millis,
                root_recovered: true,
            },
            last_accepted_block_ids,
            environment:
                "five local AvalancheGo validator processes on one host; not independent operators",
        })
    }
}

fn live_clients(config: &LiveConfig) -> Result<Vec<AvalancheRpcClient>, String> {
    config
        .node_uris
        .iter()
        .map(|uri| {
            AvalancheRpcClient::new(
                &format!("{}/ext/bc/{}", uri.trim_end_matches('/'), config.chain_id),
                Duration::from_secs(config.acceptance_timeout_seconds),
                true,
            )
        })
        .collect()
}

fn verify_live_metadata(
    clients: &[AvalancheRpcClient],
    chain_id: &str,
    all_signers: &BTreeMap<String, GovernanceSigner>,
    expected_deployment_crypto_policy: Option<&DeploymentCryptoPolicy>,
) -> Result<LiveMetadata, String> {
    if clients.len() != 5 {
        return Err("live acceptance requires exactly five RPC clients".into());
    }
    let networks = clients
        .iter()
        .map(|client| client.call("defmivm.network", json!({})))
        .collect::<Result<Vec<_>, _>>()?;
    let network = networks
        .first()
        .ok_or_else(|| "live network has no metadata".to_string())?;
    if networks.iter().any(|value| value != network)
        || network.get("chainID").and_then(Value::as_str) != Some(chain_id)
    {
        return Err("Avalanche validators disagree on the requested live network".into());
    }
    let network_id = network
        .get("networkID")
        .and_then(Value::as_u64)
        .ok_or_else(|| "live networkID is missing".to_string())?;
    let geneses = clients
        .iter()
        .map(|client| client.call("defmivm.genesis", json!({})))
        .collect::<Result<Vec<_>, _>>()?;
    let genesis = geneses
        .first()
        .ok_or_else(|| "live network has no genesis readback".to_string())?;
    if geneses.iter().any(|value| value != genesis) {
        return Err("Avalanche validators disagree on genesis".into());
    }
    let genesis = genesis
        .get("genesis")
        .ok_or_else(|| "genesis readback is missing genesis".to_string())?;
    let deployment_crypto_policy = genesis
        .get("deployment_crypto_policy")
        .cloned()
        .map(serde_json::from_value::<DeploymentCryptoPolicy>)
        .transpose()
        .map_err(|error| format!("live deployment crypto policy is invalid: {error}"))?;
    if deployment_crypto_policy.as_ref() != expected_deployment_crypto_policy {
        return Err("live genesis deployment crypto policy differs from the driver pin".into());
    }
    let timestamp = genesis
        .get("timestamp")
        .and_then(Value::as_i64)
        .ok_or_else(|| "genesis timestamp is missing".to_string())?;
    let committee = genesis
        .get("committee")
        .ok_or_else(|| "genesis committee is missing".to_string())?;
    let epoch = committee
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| "genesis committee epoch is missing".to_string())?;
    let threshold = committee
        .get("threshold")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "genesis committee threshold is missing".to_string())?;
    let members = committee
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| "genesis committee members are missing".to_string())?;
    let expected_members = all_signers
        .iter()
        .map(|(node, signer)| json!({"nodeID": node, "key": signer.verifying_key()}))
        .collect::<Vec<_>>();
    if epoch != 1 || threshold != 3 || members != &expected_members {
        return Err(
            "live genesis is not the expected epoch-1 3-of-7 public development committee".into(),
        );
    }
    Ok(LiveMetadata {
        network_id,
        genesis_timestamp: timestamp,
        committee_epoch: epoch,
        committee_threshold: threshold,
        committee_members: members.len(),
        deployment_crypto_policy,
    })
}

fn development_keys(
    deployment_crypto_policy: Option<&DeploymentCryptoPolicy>,
) -> Result<BTreeMap<String, GovernanceSigner>, String> {
    match deployment_crypto_policy {
        Some(policy) => public_development_keys_for_policy(policy),
        None => public_development_keys(),
    }
}

fn transaction_id(value: &Value) -> Result<String, String> {
    value
        .get("txID")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "L1 did not return a transaction identifier".to_string())
}

fn expected_root_strings(
    clients: &[AvalancheRpcClient],
    expected: [u8; 32],
) -> Result<Vec<String>, String> {
    let roots = clients
        .iter()
        .map(AvalancheClient::state_root)
        .collect::<Result<Vec<_>, _>>()?;
    if roots.len() != 5 || roots.iter().any(|root| *root != expected) {
        return Err(format!(
            "five-validator roots do not equal expected {}",
            hex::encode(expected)
        ));
    }
    Ok(roots.into_iter().map(hex::encode).collect())
}

fn wait_for_expected_roots(
    clients: &[AvalancheRpcClient],
    expected: [u8; 32],
    timeout: Duration,
    poll_interval: Duration,
) -> Result<Vec<String>, String> {
    let started = Instant::now();
    loop {
        let last = match clients
            .iter()
            .map(AvalancheClient::state_root)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(roots) => {
                if roots.len() == 5 && roots.iter().all(|root| *root == expected) {
                    return Ok(roots.into_iter().map(hex::encode).collect());
                }
                format!("{:?}", roots.iter().map(hex::encode).collect::<Vec<_>>())
            }
            Err(error) => error,
        };
        if started.elapsed() >= timeout {
            return Err(format!(
                "Avalanche roots did not recover to {}; last={last}",
                hex::encode(expected)
            ));
        }
        thread::sleep(poll_interval);
    }
}

fn restart_network(config: &LiveRestartConfig) -> Result<u128, String> {
    let runner = config
        .runner_path
        .canonicalize()
        .map_err(|error| format!("restart runner: {error}"))?;
    if !runner.is_file() {
        return Err("restart runnerPath is not a file".into());
    }
    let plugin_dir = config
        .plugin_dir
        .as_ref()
        .map(|path| {
            let path = path
                .canonicalize()
                .map_err(|error| format!("restart pluginDir: {error}"))?;
            if !path.is_dir() {
                return Err("restart pluginDir is not a directory".to_string());
            }
            Ok(path)
        })
        .transpose()?;
    let request_timeout = format!("--request-timeout={}s", config.timeout_seconds);
    let endpoint = format!("--endpoint={}", config.runner_endpoint);
    let started = Instant::now();
    let mut restart = Command::new(&runner);
    restart.args([
        "control",
        "restart-node",
        &config.node_name,
        &endpoint,
        &request_timeout,
    ]);
    if let Some(plugin_dir) = plugin_dir.as_ref() {
        restart.arg(format!("--plugin-dir={}", plugin_dir.display()));
    }
    let completed = command_with_timeout(restart, Duration::from_secs(config.timeout_seconds))?;
    if !completed.status.success() {
        return Err(format!(
            "Avalanche node restart failed: {}",
            command_detail(&completed.stdout, &completed.stderr)
        ));
    }
    let mut healthy = Command::new(&runner);
    healthy.args(["control", "wait-for-healthy", &endpoint, &request_timeout]);
    let completed = command_with_timeout(healthy, Duration::from_secs(config.timeout_seconds))?;
    if !completed.status.success() {
        return Err(format!(
            "Avalanche network did not recover: {}",
            command_detail(&completed.stdout, &completed.stderr)
        ));
    }
    Ok(started.elapsed().as_millis())
}

struct CapturedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn command_with_timeout(mut command: Command, timeout: Duration) -> Result<CapturedOutput, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "command has no stdout pipe".to_string())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "command has no stderr pipe".to_string())?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!("command exceeded {} seconds", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "stdout reader panicked".to_string())?
        .map_err(|error| error.to_string())?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "stderr reader panicked".to_string())?
        .map_err(|error| error.to_string())?;
    Ok(CapturedOutput {
        status,
        stdout,
        stderr,
    })
}

fn command_detail(stdout: &[u8], stderr: &[u8]) -> String {
    let bytes = if stderr.is_empty() { stdout } else { stderr };
    let start = bytes.len().saturating_sub(2_000);
    String::from_utf8_lossy(&bytes[start..]).to_string()
}

#[derive(Serialize)]
struct PendingUploadRecoveryEvidence {
    state_root: String,
    state_bytes: usize,
    state_sha256: String,
    state_readback_matches: bool,
    proof_uploaded_chunks: usize,
    proof_expected_chunks: u32,
    state_sync_summary_sha256: String,
    state_sync_snapshot_bytes: usize,
    state_sync_snapshot_sha256: String,
    state_sync_snapshot_hash: String,
    state_sync_snapshot_chunks: u32,
    state_sync_readback_matches: bool,
}

struct PersistedRecovery {
    state: State,
    state_bytes: usize,
    state_sha256: String,
    summary_sha256: String,
    snapshot_bytes: usize,
    snapshot_sha256: String,
    snapshot_hash: String,
    snapshot_chunks: u32,
}

#[derive(Serialize)]
struct CanonicalEvidence {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    deployment_crypto_policy: Option<DeploymentCryptoPolicy>,
    feature: &'static str,
    verifier: &'static str,
    deployment_mode: &'static str,
    proof_protocol: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_query_roster_sha512: Option<String>,
    transaction_limit_bytes: usize,
    block_limit_bytes: usize,
    proof_chunk_bytes: usize,
    max_proof_bytes: usize,
    fill_proof_bytes: usize,
    nofill_proof_bytes: usize,
    fill_proof_sha512: String,
    nofill_proof_sha512: String,
    fill_receipt: SettlementReceipt,
    nofill_receipt: SettlementReceipt,
    pending_upload_recovery: PendingUploadRecoveryEvidence,
    fill_transition_after_root: String,
    recovered_state_root: String,
    final_state_root: String,
    persisted_summary_sha256: String,
    persisted_snapshot_sha256: String,
    applied_blocks: u64,
    negative_gates: BTreeMap<String, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_network: Option<LiveNetworkEvidence>,
}

fn main() {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let Some(output) = arguments.first().map(PathBuf::from) else {
        usage_and_exit();
    };
    let mut live_path = None;
    let mut query_roster_pin = None;
    let mut deployment_policy_path = None;
    let mut index = 1;
    while index < arguments.len() {
        let Some(value) = arguments.get(index + 1) else {
            usage_and_exit();
        };
        match arguments[index].to_str() {
            Some("--live-config") if live_path.is_none() => {
                live_path = Some(PathBuf::from(value));
            }
            Some("--query-roster-sha512") if query_roster_pin.is_none() => {
                query_roster_pin = Some(value.to_string_lossy().into_owned());
            }
            Some("--deployment-policy") if deployment_policy_path.is_none() => {
                deployment_policy_path = Some(PathBuf::from(value));
            }
            _ => usage_and_exit(),
        }
        index += 2;
    }
    let receipt_path = output.join("canonical-receipt.json");
    let live_config = match live_path.as_deref().map(read_live_config).transpose() {
        Ok(config) => config,
        Err(error) => {
            let failure = json!({"accepted": false, "error": error});
            let _ = write_json_atomic(&receipt_path, &failure);
            eprintln!("canonical acceptance failed: {error}");
            std::process::exit(1);
        }
    };
    let deployment_crypto_policy = match deployment_policy_path
        .as_deref()
        .map(read_deployment_crypto_policy)
        .transpose()
    {
        Ok(policy) => policy,
        Err(error) => {
            let failure = json!({"accepted": false, "error": error});
            let _ = write_json_atomic(&receipt_path, &failure);
            eprintln!("canonical acceptance failed: {error}");
            std::process::exit(1);
        }
    };
    match run(
        &output,
        live_config.as_ref(),
        query_roster_pin.as_deref(),
        deployment_crypto_policy.as_ref(),
    ) {
        Ok(evidence) => {
            if let Err(error) = write_json_atomic(&receipt_path, &evidence) {
                eprintln!("canonical acceptance receipt write failed: {error}");
                std::process::exit(1);
            }
            println!("{}", receipt_path.display());
            if !evidence.accepted {
                std::process::exit(1);
            }
        }
        Err(error) => {
            let failure = json!({"accepted": false, "error": error});
            let _ = write_json_atomic(&receipt_path, &failure);
            eprintln!("canonical acceptance failed: {error}");
            std::process::exit(1);
        }
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: cocode-canonical-acceptance <public-output-dir> [--live-config FILE] [--query-roster-sha512 PIN] [--deployment-policy FILE]"
    );
    std::process::exit(2);
}

fn run(
    output: &Path,
    live_config: Option<&LiveConfig>,
    query_roster_pin: Option<&str>,
    deployment_crypto_policy: Option<&DeploymentCryptoPolicy>,
) -> Result<CanonicalEvidence, String> {
    if !output.is_dir() {
        return Err("public output directory does not exist".into());
    }
    let fill_statement = read_statement(&output.join("fill/statement.json"))?;
    let nofill_statement = read_statement(&output.join("nofill/statement.json"))?;
    validate_sequence(&fill_statement, &nofill_statement)?;
    let fill_proof = read_proof(&output.join("fill/proof.json"))?;
    let nofill_proof = read_proof(&output.join("nofill/proof.json"))?;
    let fill_manifest = ProofManifest::from_proof(fill_statement.clone(), &fill_proof)?;
    let nofill_manifest = ProofManifest::from_proof(nofill_statement.clone(), &nofill_proof)?;

    if let Some(crypto_policy) = deployment_crypto_policy {
        crypto_policy
            .validate()
            .map_err(|error| error.to_string())?;
        if fill_statement.deployment_id != crypto_policy.deployment_id
            || nofill_statement.deployment_id != crypto_policy.deployment_id
        {
            return Err("proof deployment differs from --deployment-policy".into());
        }
        if crypto_policy.mode == PqcMode::On && query_roster_pin.is_none() {
            return Err("PQC-on acceptance requires --query-roster-sha512".into());
        }
    }
    let mut harness = Harness::new(live_config, deployment_crypto_policy)?;
    let policy = match query_roster_pin {
        None => DeploymentPolicy::native_v1(fill_statement.deployment_id.clone()),
        Some(pin) => {
            DeploymentPolicy::native_query_agreement(fill_statement.deployment_id.clone(), pin)?
        }
    };
    let approval = harness.approval(policy.statement()?)?;
    let transaction = encode_policy_transaction(&policy, &approval, harness.state.root())?;
    harness.apply(transaction)?;

    let book = ResearchBookGenesis::new(
        fill_statement.deployment_id.clone(),
        fill_statement.book_id.clone(),
        [
            AccountAssetHandle::new("asset-seller-account", "traded-asset"),
            AccountAssetHandle::new("asset-buyer-account", "traded-asset"),
            AccountAssetHandle::new("cash-buyer-account", "cash-asset"),
            AccountAssetHandle::new("cash-seller-account", "cash-asset"),
        ],
        fill_statement.before_commitment.clone(),
    );
    let approval = harness.approval(book.statement()?)?;
    let transaction = encode_book_transaction(&book, &approval, harness.state.root())?;
    harness.apply(transaction)?;

    let mut negative_gates = BTreeMap::new();
    let mut wrong_before = fill_manifest.clone();
    wrong_before.statement.before_commitment =
        mutate_hex(&wrong_before.statement.before_commitment);
    negative_gates.insert(
        "wrong_authoritative_previous_book_commitment".into(),
        rejects_begin(
            &mut harness,
            "wrong_authoritative_previous_book_commitment",
            &wrong_before,
        )?,
    );
    let mut other_deployment = fill_manifest.clone();
    other_deployment.statement.deployment_id = "other-research-deployment".into();
    let deployment_rejected =
        rejects_begin(&mut harness, "mixed_deployment_or_mode", &other_deployment)?;
    let mut other_mode = fill_manifest.clone();
    other_mode.deployment_mode = "classical".into();
    negative_gates.insert(
        "mixed_deployment_or_mode".into(),
        deployment_rejected && other_mode.statement_digest().is_err(),
    );

    apply_begin(&mut harness, &fill_manifest)?;
    let first_chunk = ProofChunkUpload::from_proof(&fill_manifest, &fill_proof, 0)?;
    negative_gates.insert(
        "altered_proof_chunk".into(),
        rejects_altered_chunk(&mut harness, "altered_proof_chunk", &first_chunk)?,
    );
    apply_chunk(&mut harness, &first_chunk)?;
    let fill_commit = CommitRequest::from_manifest(&fill_manifest);
    negative_gates.insert(
        "incomplete_proof_chunks".into(),
        rejects_commit(&mut harness, "incomplete_proof_chunks", &fill_commit)?,
    );
    for index in 1..fill_manifest.chunk_count {
        let chunk = ProofChunkUpload::from_proof(&fill_manifest, &fill_proof, index)?;
        apply_chunk(&mut harness, &chunk)?;
    }
    let mut changed_after = fill_commit.clone();
    changed_after.statement.after_commitment =
        mutate_hex(&changed_after.statement.after_commitment);
    negative_gates.insert(
        "changed_output_book_commitment".into(),
        rejects_commit(
            &mut harness,
            "changed_output_book_commitment",
            &changed_after,
        )?,
    );

    let pending_uploaded_chunks = harness
        .state
        .research_cocode
        .uploaded_chunks(&fill_statement.operation_id)
        .ok_or_else(|| "fully uploaded fill proof disappeared before persistence".to_string())?;
    if pending_uploaded_chunks != fill_manifest.chunk_count as usize {
        return Err("fill proof was not fully uploaded before persistence".into());
    }
    let canonical_dir = output.join("canonical");
    fs::create_dir_all(&canonical_dir).map_err(|error| error.to_string())?;
    let pending_root = harness.state.root();
    let pending = persist_and_recover(&harness, &canonical_dir, "fill-pending")?;
    if pending.state.root() != pending_root
        || pending
            .state
            .research_cocode
            .uploaded_chunks(&fill_statement.operation_id)
            != Some(pending_uploaded_chunks)
    {
        return Err("pending fill upload did not survive canonical recovery".into());
    }
    let pending_upload_recovery = PendingUploadRecoveryEvidence {
        state_root: hex::encode(pending_root),
        state_bytes: pending.state_bytes,
        state_sha256: pending.state_sha256,
        state_readback_matches: true,
        proof_uploaded_chunks: pending_uploaded_chunks,
        proof_expected_chunks: fill_manifest.chunk_count,
        state_sync_summary_sha256: pending.summary_sha256,
        state_sync_snapshot_bytes: pending.snapshot_bytes,
        state_sync_snapshot_sha256: pending.snapshot_sha256,
        state_sync_snapshot_hash: pending.snapshot_hash,
        state_sync_snapshot_chunks: pending.snapshot_chunks,
        state_sync_readback_matches: true,
    };
    if let Some(live) = harness.live.as_mut() {
        live.restart_pending_upload(
            pending_root,
            pending.state_bytes,
            pending_uploaded_chunks,
            fill_manifest.chunk_count,
        )?;
    }
    // Commit the state-sync-decoded upload, rather than the pre-persistence
    // in-memory value, so this acceptance path exercises chunk recovery.
    harness.state = pending.state;
    let (fill_transition, fill_commit_transaction) = apply_commit(&mut harness, &fill_commit)?;
    let fill_receipt = harness
        .state
        .research_cocode
        .receipt(&fill_statement.operation_id)
        .cloned()
        .ok_or_else(|| "fill did not create a canonical settlement receipt".to_string())?;

    let committed = persist_and_recover(&harness, &canonical_dir, "fill")?;
    let mut recovered = committed.state;
    let recovered_root = recovered.root();

    let mut recovered_harness = Harness {
        state: std::mem::take(&mut recovered),
        authorizer: harness.authorizer.clone(),
        signers: harness.signers.clone(),
        parent_id: harness.parent_id,
        height: harness.height,
        timestamp: harness.timestamp,
        last_block: harness.last_block.clone(),
        live: harness.live.take(),
    };
    negative_gates.insert(
        "replayed_operation".into(),
        recovered_harness.rejects("replayed_operation", &fill_commit_transaction)?,
    );
    let mut reused_operation = nofill_manifest.clone();
    reused_operation.statement.operation_id = fill_statement.operation_id.clone();
    negative_gates.insert(
        "reused_operation_with_fresh_authorization_after_recovery".into(),
        rejects_begin(
            &mut recovered_harness,
            "reused_operation_with_fresh_authorization_after_recovery",
            &reused_operation,
        )?,
    );
    let mut stale_sequence = nofill_manifest.clone();
    stale_sequence.statement.sequence = fill_statement.sequence;
    negative_gates.insert(
        "stale_book_sequence_after_recovery".into(),
        rejects_begin(
            &mut recovered_harness,
            "stale_book_sequence_after_recovery",
            &stale_sequence,
        )?,
    );

    apply_begin(&mut recovered_harness, &nofill_manifest)?;
    for index in 0..nofill_manifest.chunk_count {
        let chunk = ProofChunkUpload::from_proof(&nofill_manifest, &nofill_proof, index)?;
        apply_chunk(&mut recovered_harness, &chunk)?;
    }
    let nofill_commit = CommitRequest::from_manifest(&nofill_manifest);
    let (nofill_transition, _) = apply_commit(&mut recovered_harness, &nofill_commit)?;
    let nofill_receipt = recovered_harness
        .state
        .research_cocode
        .receipt(&nofill_statement.operation_id)
        .cloned()
        .ok_or_else(|| "no-fill did not create a canonical settlement receipt".to_string())?;
    let final_book = recovered_harness
        .state
        .research_cocode
        .book(&fill_statement.deployment_id, &fill_statement.book_id)
        .ok_or_else(|| "canonical research book disappeared".to_string())?;
    if final_book.sequence != nofill_statement.sequence
        || final_book.commitment != nofill_statement.after_commitment
        || fill_receipt.after_commitment != nofill_receipt.before_commitment
        || nofill_transition.before_root == nofill_transition.after_root
    {
        return Err("canonical research book did not advance through both proofs".into());
    }
    recovered_harness.state.validate()?;
    let final_bytes = recovered_harness.state.encode()?;
    write_atomic(&canonical_dir.join("final-state.json"), &final_bytes)?;
    let final_roundtrip = State::decode(
        &fs::read(canonical_dir.join("final-state.json")).map_err(|error| error.to_string())?,
    )?;
    if final_roundtrip != recovered_harness.state {
        return Err("final persisted state did not recover exactly".into());
    }

    let accepted = negative_gates.values().all(|passed| *passed);
    if live_config.is_some() && !accepted {
        return Err("one or more live canonical negative gates failed".into());
    }
    let final_state_root = recovered_harness.state.root();
    let live_network = match recovered_harness.live.take() {
        Some(live) => Some(live.finish(final_state_root)?),
        None => None,
    };
    Ok(CanonicalEvidence {
        accepted,
        deployment_crypto_policy: deployment_crypto_policy.cloned(),
        feature: "research-cocode",
        verifier: if query_roster_pin.is_some() {
            "zkfmi-cosnark-trial::integration::verify_serialized_query_agreement"
        } else {
            "zkfmi-cosnark-trial::integration::verify_serialized"
        },
        deployment_mode: DEPLOYMENT_MODE,
        proof_protocol: if query_roster_pin.is_some() {
            QUERY_AGREEMENT_PROOF_PROTOCOL
        } else {
            PROOF_PROTOCOL
        },
        trusted_query_roster_sha512: query_roster_pin.map(str::to_owned),
        transaction_limit_bytes: MAX_TRANSACTION_BYTES,
        block_limit_bytes: MAX_BLOCK_BYTES,
        proof_chunk_bytes: PROOF_CHUNK_BYTES,
        max_proof_bytes: MAX_PROOF_BYTES,
        fill_proof_bytes: fill_proof.len(),
        nofill_proof_bytes: nofill_proof.len(),
        fill_proof_sha512: fill_manifest.proof_sha512,
        nofill_proof_sha512: nofill_manifest.proof_sha512,
        fill_receipt,
        nofill_receipt,
        pending_upload_recovery,
        fill_transition_after_root: hex::encode(fill_transition.after_root),
        recovered_state_root: hex::encode(recovered_root),
        final_state_root: hex::encode(final_state_root),
        persisted_summary_sha256: committed.summary_sha256,
        persisted_snapshot_sha256: committed.snapshot_sha256,
        applied_blocks: recovered_harness.height,
        negative_gates,
        live_network,
    })
}

fn validate_sequence(
    fill: &SettlementStatement,
    nofill: &SettlementStatement,
) -> Result<(), String> {
    fill.validate()?;
    nofill.validate()?;
    if fill.no_fill
        || !nofill.no_fill
        || fill.deployment_id != nofill.deployment_id
        || fill.book_id != nofill.book_id
        || fill.operation_id == nofill.operation_id
        || fill.sequence != 1
        || nofill.sequence != 2
        || fill.after_commitment != nofill.before_commitment
    {
        return Err("fill/no-fill statements do not form the required sequence 1 -> 2".into());
    }
    Ok(())
}

fn apply_begin(harness: &mut Harness, manifest: &ProofManifest) -> Result<(), String> {
    let approval = harness.approval(manifest.statement_digest()?)?;
    let transaction = encode_begin_transaction(manifest, &approval, harness.state.root())?;
    harness.apply(transaction)?;
    Ok(())
}

fn apply_chunk(harness: &mut Harness, chunk: &ProofChunkUpload) -> Result<(), String> {
    let approval = harness.approval(chunk.statement()?)?;
    let transaction = encode_chunk_transaction(chunk, &approval, harness.state.root())?;
    harness.apply(transaction)?;
    Ok(())
}

fn apply_commit(
    harness: &mut Harness,
    commit: &CommitRequest,
) -> Result<(TransitionReceipt, Vec<u8>), String> {
    let approval = harness.approval(commit.statement_digest()?)?;
    let transaction = encode_commit_transaction(commit, &approval, harness.state.root())?;
    let receipt = harness.apply(transaction.clone())?;
    Ok((receipt, transaction))
}

fn rejects_begin(
    harness: &mut Harness,
    gate: &str,
    manifest: &ProofManifest,
) -> Result<bool, String> {
    let statement = manifest.statement_digest()?;
    let approval = harness.approval(statement)?;
    let transaction = encode_begin_transaction(manifest, &approval, harness.state.root())?;
    harness.rejects(gate, &transaction)
}

fn rejects_commit(
    harness: &mut Harness,
    gate: &str,
    commit: &CommitRequest,
) -> Result<bool, String> {
    let approval = harness.approval(commit.statement_digest()?)?;
    let transaction = encode_commit_transaction(commit, &approval, harness.state.root())?;
    harness.rejects(gate, &transaction)
}

fn rejects_altered_chunk(
    harness: &mut Harness,
    gate: &str,
    chunk: &ProofChunkUpload,
) -> Result<bool, String> {
    let approval = harness.approval(chunk.statement()?)?;
    let mut altered = chunk.clone();
    let mut bytes = BASE64
        .decode(&altered.data)
        .map_err(|error| error.to_string())?;
    bytes[0] ^= 1;
    altered.data = BASE64.encode(bytes);
    let transaction = TransactionEnvelope::new(
        "defmivm.issueResearchCoCodeProofChunk",
        json!({
            "chunk": altered,
            "approval": approval_json(&approval),
            "expectedBeforeRoot": hex::encode(harness.state.root()),
        }),
    )?
    .encode()?;
    harness.rejects(gate, &transaction)
}

fn persist_and_recover(
    harness: &Harness,
    directory: &Path,
    stem: &str,
) -> Result<PersistedRecovery, String> {
    let block = harness
        .last_block
        .as_ref()
        .ok_or_else(|| "no accepted block is available for persistence".to_string())?;
    let chain_id = Id::digest(b"cocode-canonical-acceptance-chain-v1");
    let genesis_hash = Id::digest(b"cocode-canonical-acceptance-genesis-bytes-v1");

    let state_path = directory.join(format!("{stem}-state.json"));
    let state_bytes = harness.state.encode()?;
    let state_len = state_bytes.len();
    let state_sha256 = sha256_hex(&state_bytes);
    write_atomic(&state_path, &state_bytes)?;
    drop(state_bytes);
    let persisted_state = fs::read(&state_path).map_err(|error| error.to_string())?;
    let state_readback = State::decode(&persisted_state)?;
    if state_readback != harness.state || sha256_hex(&persisted_state) != state_sha256 {
        return Err("persisted canonical state did not recover exactly".into());
    }
    drop(persisted_state);
    drop(state_readback);

    let (summary, snapshot) =
        build_summary(NETWORK_ID, chain_id, genesis_hash, block, &harness.state)?;
    let summary_bytes = summary.encode()?;
    let summary_sha256 = sha256_hex(&summary_bytes);
    let snapshot_len = snapshot.len();
    let snapshot_sha256 = sha256_hex(&snapshot);
    let snapshot_hash = hex::encode(summary.snapshot_hash);
    let snapshot_chunks = summary.chunk_count;
    let summary_path = directory.join(format!("{stem}-summary.bin"));
    let snapshot_path = directory.join(format!("{stem}-snapshot.bin"));
    write_atomic(&summary_path, &summary_bytes)?;
    write_atomic(&snapshot_path, &snapshot)?;
    drop(summary_bytes);
    drop(snapshot);
    let persisted_summary = fs::read(&summary_path).map_err(|error| error.to_string())?;
    let persisted_snapshot = fs::read(&snapshot_path).map_err(|error| error.to_string())?;
    if sha256_hex(&persisted_summary) != summary_sha256
        || sha256_hex(&persisted_snapshot) != snapshot_sha256
    {
        return Err("persisted canonical snapshot bytes changed during readback".into());
    }
    let decoded_summary = StateSummary::decode(&persisted_summary)?;
    let decoded = decode_snapshot(&decoded_summary, &persisted_snapshot)?;
    if decoded.state != harness.state || decoded.block != *block {
        return Err("persisted canonical snapshot did not recover exactly".into());
    }
    Ok(PersistedRecovery {
        state: decoded.state,
        state_bytes: state_len,
        state_sha256,
        summary_sha256,
        snapshot_bytes: snapshot_len,
        snapshot_sha256,
        snapshot_hash,
        snapshot_chunks,
    })
}

fn read_live_config(path: &Path) -> Result<LiveConfig, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 1_048_576 {
        return Err("live config must be a regular file containing 1..=1 MiB".into());
    }
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let config = LiveConfig::deserialize(&mut deserializer)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    deserializer
        .end()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    config.validate()?;
    Ok(config)
}

fn read_deployment_crypto_policy(path: &Path) -> Result<DeploymentCryptoPolicy, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 65_536 {
        return Err("deployment policy must be a regular file containing 1..=64 KiB".into());
    }
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let policy = DeploymentCryptoPolicy::deserialize(&mut deserializer)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    deserializer
        .end()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    policy.validate().map_err(|error| error.to_string())?;
    Ok(policy)
}

fn read_statement(path: &Path) -> Result<SettlementStatement, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let statement = SettlementStatement::deserialize(&mut deserializer)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    deserializer
        .end()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    statement.validate()?;
    Ok(statement)
}

fn read_proof(path: &Path) -> Result<Vec<u8>, String> {
    let length = fs::metadata(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .len();
    if length == 0 || length > MAX_PROOF_BYTES as u64 {
        return Err(format!(
            "{} proof size is outside 1..=256 MiB",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn mutate_hex(value: &str) -> String {
    let mut bytes = value.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("hex is UTF-8")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output path has no UTF-8 file name".to_string())?;
    let temporary = path.with_file_name(format!(".{file_name}.tmp"));
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())
}
