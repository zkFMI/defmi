//! End-to-end acceptance for the QOMM Rust VM under AvalancheGo consensus.

use ed25519_dalek::{SigningKey, VerifyingKey};
use qomm_defmi::avalanche::{AvalancheClient, AvalancheRpcClient, FacilityAvalancheBridge};
use qomm_defmi::facility::{
    AccountOpening, AssetDefinition, AssetKind, DefmiFacility, QuorumApproval, QuorumAuthorizer,
    SettlementOrder, StateLeg,
};
use qomm_harness::{next_value, HarnessResult};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Options {
    chain_id: String,
    node_uris: Vec<String>,
    projection: PathBuf,
    out: PathBuf,
    runner: Option<PathBuf>,
    avalanchego: Option<PathBuf>,
    runner_endpoint: String,
    restart_node: String,
    plugin_dir: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> HarnessResult<()> {
    let options = parse_args()?;
    let result = run(&options)?;
    if let Some(parent) = options
        .out
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let temporary = PathBuf::from(format!("{}.tmp", options.out.to_string_lossy()));
    let mut rendered = serde_json::to_string_pretty(&result)?;
    rendered.push('\n');
    fs::write(&temporary, rendered)?;
    fs::rename(&temporary, &options.out)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn run(options: &Options) -> HarnessResult<Value> {
    let started = Instant::now();
    let mut rpc_clients = clients(&options.node_uris, &options.chain_id)?;
    let network = rpc_clients[0]
        .call("defmivm.network", json!({}))
        .map_err(string_error)?;
    if network.get("chainID").and_then(Value::as_str) != Some(&options.chain_id) {
        return Err("Avalanche RPC chain identifier does not match the requested L1".into());
    }
    let initial_roots = rpc_clients
        .iter()
        .map(AvalancheClient::state_root)
        .collect::<Result<Vec<_>, _>>()
        .map_err(string_error)?;
    if initial_roots.windows(2).any(|roots| roots[0] != roots[1]) {
        return Err("Avalanche nodes disagree before the acceptance run".into());
    }

    let (authorizer, keys) = committee(&options.chain_id)?;
    let receipt_key = SigningKey::from_bytes(&digest("qomm-avalanche-acceptance-receipt-key-v1"));
    let facility =
        DefmiFacility::open(&options.projection, authorizer, receipt_key).map_err(string_error)?;
    let bridge = FacilityAvalancheBridge::new(&facility, &rpc_clients[0]);
    let mut operation_timings = serde_json::Map::new();

    let jpy = AssetDefinition {
        asset_id: digest("asset:JPY"),
        code: "JPY".to_string(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: digest("terms:JPY"),
    };
    let before = Instant::now();
    let bootstrap_root = facility.state_root().map_err(string_error)?;
    let bootstrap_approval = approval(
        &facility.authorizer,
        &keys,
        jpy.statement().map_err(string_error)?,
        bootstrap_root,
    )?;
    let bootstrap = bridge
        .register_asset(&jpy, &bootstrap_approval)
        .map_err(string_error)?;
    operation_timings.insert(
        "bootstrap_or_recovery_ms".to_string(),
        json!(before.elapsed().as_secs_f64() * 1000.0),
    );

    let instrument = AssetDefinition {
        asset_id: digest("asset:avalanche-acceptance-v1"),
        code: "QOMM-ACCEPT-V1".to_string(),
        kind: AssetKind::Other,
        decimals: 0,
        terms_digest: digest("terms:avalanche-acceptance-v1"),
    };
    let local_before_crash = facility.state_root().map_err(string_error)?;
    let instrument_approval = approval(
        &facility.authorizer,
        &keys,
        instrument.statement().map_err(string_error)?,
        local_before_crash,
    )?;
    let direct_tx = rpc_clients[0]
        .issue_asset(&instrument, &instrument_approval, local_before_crash)
        .map_err(string_error)?;
    let direct_acceptance = rpc_clients[0]
        .wait_accepted(
            &direct_tx,
            Duration::from_secs(30),
            Duration::from_millis(200),
        )
        .map_err(string_error)?;
    if facility.state_root().map_err(string_error)? != local_before_crash {
        return Err("local projection changed before recovery was requested".into());
    }
    let before = Instant::now();
    let recovered = bridge
        .register_asset(&instrument, &instrument_approval)
        .map_err(string_error)?;
    operation_timings.insert(
        "crash_window_recovery_ms".to_string(),
        json!(before.elapsed().as_secs_f64() * 1000.0),
    );
    if recovered.tx_id != direct_acceptance.tx_id {
        return Err("crash recovery created a second transaction".into());
    }

    let left = AccountOpening {
        handle: digest("account:avalanche-acceptance-left-v1"),
        asset_id: instrument.asset_id,
        commitment: digest("commitment:left:0:v1"),
        issuance_nonce: digest("issuance:left:v1"),
    };
    let right = AccountOpening {
        handle: digest("account:avalanche-acceptance-right-v1"),
        asset_id: instrument.asset_id,
        commitment: digest("commitment:right:0:v1"),
        issuance_nonce: digest("issuance:right:v1"),
    };
    let before = Instant::now();
    let left_approval = approval(
        &facility.authorizer,
        &keys,
        left.statement().map_err(string_error)?,
        facility.state_root().map_err(string_error)?,
    )?;
    let left_accepted = bridge
        .open_account(&left, &left_approval)
        .map_err(string_error)?;
    let right_approval = approval(
        &facility.authorizer,
        &keys,
        right.statement().map_err(string_error)?,
        facility.state_root().map_err(string_error)?,
    )?;
    let right_accepted = bridge
        .open_account(&right, &right_approval)
        .map_err(string_error)?;
    operation_timings.insert(
        "two_accounts_ms".to_string(),
        json!(before.elapsed().as_secs_f64() * 1000.0),
    );

    let order = SettlementOrder {
        operation_id: digest("operation:avalanche-acceptance-v1"),
        nullifier: digest("nullifier:avalanche-acceptance-v1"),
        deadline: 4_102_444_800,
        payment_instruction_digest: digest("zkpi:avalanche-acceptance-v1"),
        proof_digest: digest("proof:avalanche-acceptance-v1"),
        market_statement_digest: digest("market:avalanche-acceptance-v1"),
        legs: vec![
            StateLeg {
                handle: left.handle,
                asset_id: instrument.asset_id,
                before_commitment: digest("commitment:left:0:v1"),
                after_commitment: digest("commitment:left:1:v1"),
                before_sequence: 0,
            },
            StateLeg {
                handle: right.handle,
                asset_id: instrument.asset_id,
                before_commitment: digest("commitment:right:0:v1"),
                after_commitment: digest("commitment:right:1:v1"),
                before_sequence: 0,
            },
        ],
    };
    let order_approval = approval(
        &facility.authorizer,
        &keys,
        order.statement().map_err(string_error)?,
        facility.state_root().map_err(string_error)?,
    )?;
    let before = Instant::now();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (local_receipt, settlement) = bridge
        .settle(&order, &order_approval, now)
        .map_err(string_error)?;
    operation_timings.insert(
        "settlement_ms".to_string(),
        json!(before.elapsed().as_secs_f64() * 1000.0),
    );
    let final_root = facility.state_root().map_err(string_error)?;
    let roots_before_restart = wait_for_roots(&rpc_clients, final_root, 30.0)?;
    let mut restart_ms = None;
    let mut roots_after_restart = roots_before_restart.clone();
    if let Some(runner) = options.runner.as_deref() {
        restart_ms = Some(restart_node(
            runner,
            &options.runner_endpoint,
            &options.restart_node,
            options.plugin_dir.as_deref(),
        )?);
        rpc_clients = clients(&options.node_uris, &options.chain_id)?;
        roots_after_restart = wait_for_roots(&rpc_clients, final_root, 30.0)?;
    }

    let last_accepted = rpc_clients[0]
        .call("defmivm.lastAccepted", json!({}))
        .map_err(string_error)?;
    let verified_chain = facility.verify_receipt_chain().map_err(string_error)?;
    if !verified_chain {
        return Err("local settlement receipt chain did not verify".into());
    }
    let local_digest = local_receipt.digest().map_err(string_error)?;
    Ok(json!({
        "passed": true,
        "environment": format!(
            "{} local AvalancheGo processes on one host; not geographically separate validators",
            rpc_clients.len()
        ),
        "evm_used": false,
        "network": network,
        "chain_id": options.chain_id,
        "external_binaries": {
            "avalanchego": tool_record(options.avalanchego.as_deref(), true)?,
            "avalanche_network_runner": tool_record(options.runner.as_deref(), false)?,
        },
        "nodes": rpc_clients.len(),
        "initial_roots": initial_roots.iter().map(hex::encode).collect::<Vec<_>>(),
        "final_root": hex::encode(final_root),
        "roots_before_restart": roots_before_restart,
        "roots_after_restart": roots_after_restart,
        "crash_recovery": {
            "same_transaction": recovered.tx_id == direct_acceptance.tx_id,
            "transaction_id": recovered.tx_id,
            "accepted_height": recovered.height,
        },
        "accepted_transitions": {
            "bootstrap_asset": {"tx_id": bootstrap.tx_id, "height": bootstrap.height},
            "instrument_asset": {"tx_id": recovered.tx_id, "height": recovered.height},
            "left_account": {"tx_id": left_accepted.tx_id, "height": left_accepted.height},
            "right_account": {"tx_id": right_accepted.tx_id, "height": right_accepted.height},
            "settlement": {"tx_id": settlement.tx_id, "height": settlement.height},
        },
        "local_receipt": {
            "digest": hex::encode(local_digest),
            "before_root": hex::encode(local_receipt.before_root),
            "after_root": hex::encode(local_receipt.after_root),
            "verified_chain": verified_chain,
        },
        "operation_timings_ms": Value::Object(operation_timings),
        "restart": {
            "node": options.restart_node,
            "elapsed_ms": restart_ms,
            "root_recovered": roots_after_restart == roots_before_restart,
        },
        "last_accepted_block_id": last_accepted
            .get("blockID")
            .and_then(Value::as_str)
            .ok_or("lastAccepted response has no blockID")?,
        "elapsed_seconds": started.elapsed().as_secs_f64(),
    }))
}

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn committee(domain: &str) -> HarnessResult<(QuorumAuthorizer, BTreeMap<String, SigningKey>)> {
    let keys = (0..7)
        .map(|index| {
            (
                format!("node-{index}"),
                SigningKey::from_bytes(&digest(&format!("key:{index}"))),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let nodes = keys
        .iter()
        .map(|(name, key)| (name.clone(), key.verifying_key()))
        .collect::<BTreeMap<String, VerifyingKey>>();
    let authorizer =
        QuorumAuthorizer::new(nodes, 3, 1, domain.to_string()).map_err(string_error)?;
    Ok((authorizer, keys))
}

fn approval(
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    statement: [u8; 32],
    before_root: [u8; 32],
) -> HarnessResult<QuorumApproval> {
    let first_three = keys
        .iter()
        .take(3)
        .map(|(name, key)| (name.clone(), key.clone()))
        .collect::<BTreeMap<_, _>>();
    authorizer
        .approve(statement, before_root, &first_three)
        .map_err(string_error)
}

fn clients(node_uris: &[String], chain_id: &str) -> HarnessResult<Vec<AvalancheRpcClient>> {
    node_uris
        .iter()
        .map(|uri| {
            AvalancheRpcClient::new(
                &format!("{}/ext/bc/{chain_id}", uri.trim_end_matches('/')),
                Duration::from_secs(30),
                true,
            )
            .map_err(string_error)
        })
        .collect()
}

fn wait_for_roots(
    rpc_clients: &[AvalancheRpcClient],
    expected: [u8; 32],
    timeout_seconds: f64,
) -> HarnessResult<Vec<String>> {
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_seconds);
    let mut last = Vec::new();
    loop {
        if let Ok(roots) = rpc_clients
            .iter()
            .map(AvalancheClient::state_root)
            .collect::<Result<Vec<_>, _>>()
        {
            last = roots.iter().map(hex::encode).collect();
            if !roots.is_empty() && roots.iter().all(|root| *root == expected) {
                return Ok(last);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Avalanche nodes did not converge to {}; last={last:?}",
                hex::encode(expected)
            )
            .into());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn restart_node(
    runner: &Path,
    runner_endpoint: &str,
    node: &str,
    plugin_dir: Option<&Path>,
) -> HarnessResult<f64> {
    let started = Instant::now();
    let mut restart = Command::new(runner);
    restart.args([
        "control",
        "restart-node",
        node,
        &format!("--endpoint={runner_endpoint}"),
        "--request-timeout=3m",
    ]);
    if let Some(plugin_dir) = plugin_dir {
        restart.arg(format!(
            "--plugin-dir={}",
            plugin_dir.canonicalize()?.display()
        ));
    }
    let completed = output_with_timeout(restart, Duration::from_secs(180))?;
    if !completed.status.success() {
        return Err(format!(
            "Avalanche node restart failed: {}",
            command_detail(&completed.stdout, &completed.stderr)
        )
        .into());
    }

    let mut healthy = Command::new(runner);
    healthy.args([
        "control",
        "wait-for-healthy",
        &format!("--endpoint={runner_endpoint}"),
        "--request-timeout=3m",
    ]);
    let completed = output_with_timeout(healthy, Duration::from_secs(180))?;
    if !completed.status.success() {
        return Err(format!(
            "Avalanche network did not recover: {}",
            command_detail(&completed.stdout, &completed.stderr)
        )
        .into());
    }
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

fn tool_record(path: Option<&Path>, require_version: bool) -> HarnessResult<Value> {
    let Some(path) = path else {
        return Ok(Value::Null);
    };
    let resolved = path.canonicalize()?;
    if !resolved.is_file() {
        return Err("acceptance tool path is not a file".into());
    }
    let mut version = Command::new(&resolved);
    version.arg("--version");
    let completed = output_with_timeout(version, Duration::from_secs(20))?;
    if require_version && !completed.status.success() {
        return Err("acceptance tool did not report its version".into());
    }
    let displayed = if completed.status.success() {
        let bytes = if completed.stdout.is_empty() {
            &completed.stderr
        } else {
            &completed.stdout
        };
        Some(String::from_utf8_lossy(bytes).trim().to_string())
    } else {
        None
    };
    let mut file = File::open(&resolved)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(json!({
        "version": displayed,
        "version_probe_supported": completed.status.success(),
        "version_probe_exit_code": completed.status.code(),
        "sha256": hex::encode(hash.finalize()),
    }))
}

struct CapturedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn output_with_timeout(mut command: Command, timeout: Duration) -> HarnessResult<CapturedOutput> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or("command has no stdout pipe")?;
    let mut stderr = child.stderr.take().ok_or("command has no stderr pipe")?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!("command exceeded {} seconds", timeout.as_secs()).into());
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "stdout reader panicked")??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "stderr reader panicked")??;
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

fn string_error(error: String) -> Box<dyn std::error::Error> {
    error.into()
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options {
        chain_id: String::new(),
        node_uris: Vec::new(),
        projection: PathBuf::new(),
        out: qomm_harness::repo_root().join("artifacts/avalanche_l1_acceptance.json"),
        runner: None,
        avalanchego: None,
        runner_endpoint: "localhost:8080".to_string(),
        restart_node: "node3".to_string(),
        plugin_dir: None,
    };
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--chain-id") => options.chain_id = string_arg(&mut args, "--chain-id")?,
            Some("--node-uri") => options.node_uris.push(string_arg(&mut args, "--node-uri")?),
            Some("--projection") => {
                options.projection = PathBuf::from(next_value(&mut args, "--projection")?)
            }
            Some("--out") => options.out = PathBuf::from(next_value(&mut args, "--out")?),
            Some("--runner") => {
                options.runner = Some(PathBuf::from(next_value(&mut args, "--runner")?))
            }
            Some("--avalanchego") => {
                options.avalanchego = Some(PathBuf::from(next_value(&mut args, "--avalanchego")?))
            }
            Some("--runner-endpoint") => {
                options.runner_endpoint = string_arg(&mut args, "--runner-endpoint")?
            }
            Some("--restart-node") => {
                options.restart_node = string_arg(&mut args, "--restart-node")?
            }
            Some("--plugin-dir") => {
                options.plugin_dir = Some(PathBuf::from(next_value(&mut args, "--plugin-dir")?))
            }
            Some("-h" | "--help") => {
                println!(
                    "usage: run_avalanche_l1_acceptance --chain-id ID --node-uri URI \
                     [--node-uri URI ...] --projection PATH [--out PATH] [--runner PATH] \
                     [--avalanchego PATH] [--runner-endpoint HOST:PORT] \
                     [--restart-node NAME] [--plugin-dir PATH]"
                );
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument {}", argument.to_string_lossy()).into()),
        }
    }
    if options.chain_id.is_empty() {
        return Err("--chain-id is required".into());
    }
    if options.node_uris.len() < 3 {
        return Err("at least three AvalancheGo nodes are required".into());
    }
    if options.projection.as_os_str().is_empty() {
        return Err("--projection is required".into());
    }
    Ok(options)
}

fn string_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> HarnessResult<String> {
    next_value(args, name)?
        .into_string()
        .map_err(|_| format!("argument {name} is not valid UTF-8").into())
}
