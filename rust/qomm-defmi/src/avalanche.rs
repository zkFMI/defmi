//! Fail-closed Avalanche custom-VM JSON-RPC client and projection bridge.

use crate::facility::{
    AccountOpening, AssetDefinition, DefmiFacility, QuorumApproval, SettlementOrder,
    SettlementReceipt,
};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_RESPONSE: usize = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedTransition {
    pub tx_id: String,
    pub block_id: String,
    pub height: u64,
    pub statement: [u8; 32],
    pub before_root: [u8; 32],
    pub after_root: [u8; 32],
}

impl AcceptedTransition {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?;
        let parse = |name: &str| -> Result<[u8; 32], String> {
            hex::decode(
                object
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?,
            )
            .map_err(|_| "L1 acceptance receipt has invalid field widths".to_string())?
            .try_into()
            .map_err(|_| "L1 acceptance receipt has invalid field widths".to_string())
        };
        Ok(Self {
            tx_id: object
                .get("txID")
                .and_then(Value::as_str)
                .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?
                .to_string(),
            block_id: object
                .get("blockID")
                .and_then(Value::as_str)
                .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?
                .to_string(),
            height: object
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| "L1 returned a malformed acceptance receipt".to_string())?,
            statement: parse("statement")?,
            before_root: parse("beforeRoot")?,
            after_root: parse("afterRoot")?,
        })
    }
}

fn approval_json(approval: &QuorumApproval) -> Value {
    json!({
        "statement": hex::encode(approval.statement),
        "signerEpoch": approval.signer_epoch,
        "domain": approval.domain,
        "beforeRoot": hex::encode(approval.before_root),
        "approvals": approval.approvals.iter().map(|signed| json!({
            "nodeID": signed.node_id,
            "signature": hex::encode(signed.signature.to_bytes()),
        })).collect::<Vec<_>>(),
    })
}

fn asset_json(asset: &AssetDefinition) -> Value {
    json!({
        "assetID": hex::encode(asset.asset_id),
        "code": asset.code,
        "kind": asset.kind.as_str(),
        "decimals": asset.decimals,
        "termsDigest": hex::encode(asset.terms_digest),
    })
}

fn opening_json(opening: &AccountOpening) -> Value {
    json!({
        "handle": hex::encode(opening.handle),
        "assetID": hex::encode(opening.asset_id),
        "commitment": hex::encode(opening.commitment),
        "issuanceNonce": hex::encode(opening.issuance_nonce),
    })
}

fn order_json(order: &SettlementOrder) -> Value {
    json!({
        "operationID": hex::encode(order.operation_id),
        "nullifier": hex::encode(order.nullifier),
        "deadline": order.deadline,
        "paymentInstructionDigest": hex::encode(order.payment_instruction_digest),
        "proofDigest": hex::encode(order.proof_digest),
        "marketStatementDigest": hex::encode(order.market_statement_digest),
        "legs": order.legs.iter().map(|leg| json!({
            "handle": hex::encode(leg.handle),
            "assetID": hex::encode(leg.asset_id),
            "beforeCommitment": hex::encode(leg.before_commitment),
            "afterCommitment": hex::encode(leg.after_commitment),
            "beforeSequence": leg.before_sequence,
        })).collect::<Vec<_>>(),
    })
}

#[derive(Clone, Debug)]
struct Endpoint {
    tls: bool,
    host: String,
    port: u16,
    path: String,
    authority: String,
}

fn parse_endpoint(endpoint: &str, allow_insecure_localhost: bool) -> Result<Endpoint, String> {
    let (tls, rest) = if let Some(rest) = endpoint.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("Avalanche endpoint must be an absolute HTTP(S) URL".into());
    };
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_string()), |(authority, path)| {
            (authority, format!("/{path}"))
        });
    if authority.is_empty() || authority.contains('@') {
        return Err("Avalanche endpoint must be an absolute HTTP(S) URL".into());
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(|| "Avalanche endpoint has an invalid IPv6 host".to_string())?;
        let port = suffix
            .strip_prefix(':')
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|_| "Avalanche endpoint has an invalid port".to_string())?
            .unwrap_or(if tls { 443 } else { 80 });
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host.to_string(),
                port.parse::<u16>()
                    .map_err(|_| "Avalanche endpoint has an invalid port".to_string())?,
            ),
            _ => (authority.to_string(), if tls { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        return Err("Avalanche endpoint must be an absolute HTTP(S) URL".into());
    }
    let loopback = matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1");
    if !tls && !(allow_insecure_localhost && loopback) {
        return Err(
            "plaintext Avalanche RPC is allowed only for an explicit localhost test".into(),
        );
    }
    Ok(Endpoint {
        tls,
        host,
        port,
        path,
        authority: authority.to_string(),
    })
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "Avalanche RPC returned malformed chunked HTTP".to_string())?;
        let length = std::str::from_utf8(&body[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|length| usize::from_str_radix(length.trim(), 16).ok())
            .ok_or_else(|| "Avalanche RPC returned malformed chunked HTTP".to_string())?;
        body = &body[line_end + 2..];
        if length == 0 {
            return Ok(decoded);
        }
        if body.len() < length + 2 || &body[length..length + 2] != b"\r\n" {
            return Err("Avalanche RPC returned malformed chunked HTTP".into());
        }
        decoded.extend_from_slice(&body[..length]);
        if decoded.len() > MAX_RESPONSE {
            return Err("Avalanche RPC response exceeded one MiB".into());
        }
        body = &body[length + 2..];
    }
}

fn http_post(endpoint: &Endpoint, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    let mut stream: Box<dyn ReadWrite> = if endpoint.tls {
        let mut builder =
            SslConnector::builder(SslMethod::tls_client()).map_err(|error| error.to_string())?;
        builder.set_verify(SslVerifyMode::PEER);
        builder
            .set_default_verify_paths()
            .map_err(|error| error.to_string())?;
        Box::new(
            builder
                .build()
                .connect(&endpoint.host, tcp)
                .map_err(|error| format!("Avalanche RPC TLS authentication failed: {error}"))?,
        )
    } else {
        Box::new(tcp)
    };
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path,
        endpoint.authority,
        body.len()
    )
    .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    stream
        .write_all(body)
        .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    let mut raw = Vec::new();
    stream
        .take((MAX_RESPONSE + 65_536 + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| format!("Avalanche RPC transport failed: {error}"))?;
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "Avalanche RPC returned malformed HTTP".to_string())?;
    let headers = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "Avalanche RPC returned malformed HTTP headers".to_string())?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "Avalanche RPC returned malformed HTTP status".to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "Avalanche RPC HTTP endpoint returned status {status}"
        ));
    }
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = &raw[header_end + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    if body.len() > MAX_RESPONSE {
        return Err("Avalanche RPC response exceeded one MiB".into());
    }
    Ok(body)
}

type Transport = dyn Fn(&[u8], Duration) -> Result<Vec<u8>, String> + Send + Sync;

pub struct AvalancheRpcClient {
    timeout: Duration,
    next_id: AtomicU64,
    transport: Arc<Transport>,
}

impl AvalancheRpcClient {
    pub fn new(
        endpoint: &str,
        timeout: Duration,
        allow_insecure_localhost: bool,
    ) -> Result<Self, String> {
        if timeout.is_zero() {
            return Err("RPC timeout must be positive".into());
        }
        let endpoint = parse_endpoint(endpoint, allow_insecure_localhost)?;
        Ok(Self {
            timeout,
            next_id: AtomicU64::new(1),
            transport: Arc::new(move |body, timeout| http_post(&endpoint, body, timeout)),
        })
    }

    pub fn with_transport<F>(
        endpoint: &str,
        timeout: Duration,
        allow_insecure_localhost: bool,
        transport: F,
    ) -> Result<Self, String>
    where
        F: Fn(&[u8], Duration) -> Result<Vec<u8>, String> + Send + Sync + 'static,
    {
        parse_endpoint(endpoint, allow_insecure_localhost)?;
        if timeout.is_zero() {
            return Err("RPC timeout must be positive".into());
        }
        Ok(Self {
            timeout,
            next_id: AtomicU64::new(1),
            transport: Arc::new(transport),
        })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }))
        .map_err(|error| error.to_string())?;
        let raw = (self.transport)(&body, self.timeout)?;
        if raw.len() > MAX_RESPONSE {
            return Err("Avalanche RPC response exceeded one MiB".into());
        }
        let envelope: Value = serde_json::from_slice(&raw)
            .map_err(|_| "Avalanche RPC returned invalid JSON".to_string())?;
        if envelope.get("id").and_then(Value::as_u64) != Some(request_id) {
            return Err("Avalanche RPC response identifier does not match".into());
        }
        if let Some(error) = envelope.get("error").filter(|value| !value.is_null()) {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(format!("Avalanche RPC rejected the request: {message}"));
        }
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| "Avalanche RPC response has no result".to_string())
    }

    fn transaction_id(result: &Value) -> Result<String, String> {
        result
            .get("txID")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "L1 did not return a transaction identifier".to_string())
    }
}

pub trait AvalancheClient: Send + Sync {
    fn state_root(&self) -> Result<[u8; 32], String>;
    fn issue_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String>;
    fn issue_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String>;
    fn issue_settlement(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String>;
    fn wait_accepted(
        &self,
        tx_id: &str,
        timeout: Duration,
        poll: Duration,
    ) -> Result<AcceptedTransition, String>;
}

impl AvalancheClient for AvalancheRpcClient {
    fn state_root(&self) -> Result<[u8; 32], String> {
        let result = self.call("defmivm.stateRoot", json!({}))?;
        let raw = result
            .get("stateRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| "L1 returned an invalid state root".to_string())?;
        hex::decode(raw)
            .map_err(|_| "L1 returned an invalid state root".to_string())?
            .try_into()
            .map_err(|_| "L1 state root must be 32 bytes".to_string())
    }

    fn issue_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueAsset",
            json!({
                "asset": asset_json(asset),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueAccount",
            json!({
                "opening": opening_json(opening),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn issue_settlement(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        expected_before_root: [u8; 32],
    ) -> Result<String, String> {
        Self::transaction_id(&self.call(
            "defmivm.issueSettlement",
            json!({
                "order": order_json(order),
                "approval": approval_json(approval),
                "expectedBeforeRoot": hex::encode(expected_before_root),
            }),
        )?)
    }

    fn wait_accepted(
        &self,
        tx_id: &str,
        timeout: Duration,
        poll: Duration,
    ) -> Result<AcceptedTransition, String> {
        if timeout.is_zero() || poll.is_zero() {
            return Err("acceptance timeout and polling interval must be positive".into());
        }
        let started = Instant::now();
        loop {
            let result = self.call("defmivm.txStatus", json!({"txID": tx_id}))?;
            let status = result.get("status").and_then(Value::as_str);
            match status {
                Some("accepted") => return AcceptedTransition::parse(&result),
                Some("rejected") => {
                    return Err(format!(
                        "Avalanche consensus rejected transaction {tx_id}: {}",
                        result
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("unspecified")
                    ));
                }
                Some("pending" | "processing" | "unknown") => {}
                other => return Err(format!("L1 returned unknown transaction status {other:?}")),
            }
            if started.elapsed() >= timeout {
                return Err(format!(
                    "Avalanche transaction {tx_id} was not accepted in time"
                ));
            }
            thread::sleep(poll);
        }
    }
}

pub struct FacilityAvalancheBridge<'a, C: AvalancheClient> {
    pub facility: &'a DefmiFacility,
    pub client: &'a C,
}

impl<'a, C: AvalancheClient> FacilityAvalancheBridge<'a, C> {
    pub const fn new(facility: &'a DefmiFacility, client: &'a C) -> Self {
        Self { facility, client }
    }

    fn require_approval(
        &self,
        statement: &[u8; 32],
        before: &[u8; 32],
        approval: &QuorumApproval,
    ) -> Result<(), String> {
        if self.facility.authorizer.verify(statement, before, approval) {
            Ok(())
        } else {
            Err("the transition approval is not bound to this L1 and state root".into())
        }
    }

    fn check(
        accepted: &AcceptedTransition,
        statement: &[u8; 32],
        before: &[u8; 32],
    ) -> Result<(), String> {
        if accepted.statement != *statement {
            return Err("Avalanche accepted a different authorized statement".into());
        }
        if accepted.before_root != *before {
            return Err("Avalanche applied the transition to an unexpected state root".into());
        }
        Ok(())
    }

    pub fn register_asset(
        &self,
        asset: &AssetDefinition,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let before = self.facility.state_root()?;
        let statement = asset.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_asset(asset, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            Duration::from_secs(30),
            Duration::from_millis(200),
        )?;
        Self::check(&accepted, &statement, &before)?;
        self.facility.register_asset(asset, approval)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("asset projection root differs from Avalanche".into());
        }
        Ok(accepted)
    }

    pub fn open_account(
        &self,
        opening: &AccountOpening,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let before = self.facility.state_root()?;
        let statement = opening.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_account(opening, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            Duration::from_secs(30),
            Duration::from_millis(200),
        )?;
        Self::check(&accepted, &statement, &before)?;
        self.facility.open_account(opening, approval)?;
        if self.facility.state_root()? != accepted.after_root {
            return Err("account projection root differs from Avalanche".into());
        }
        Ok(accepted)
    }

    pub fn settle(
        &self,
        order: &SettlementOrder,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(SettlementReceipt, AcceptedTransition), String> {
        let before = self.facility.state_root()?;
        let statement = order.statement()?;
        self.require_approval(&statement, &before, approval)?;
        let transaction = self.client.issue_settlement(order, approval, before)?;
        let accepted = self.client.wait_accepted(
            &transaction,
            Duration::from_secs(30),
            Duration::from_millis(200),
        )?;
        Self::check(&accepted, &statement, &before)?;
        let receipt = self.facility.settle(order, approval, now)?;
        if receipt.before_root != accepted.before_root || receipt.after_root != accepted.after_root
        {
            return Err("settlement projection root differs from Avalanche".into());
        }
        Ok((receipt, accepted))
    }
}
