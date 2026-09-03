//! Small Ethereum JSON-RPC transport shared by the measurement collectors.

use serde_json::{json, Value};
use std::process::Command;
use std::thread;
use std::time::Duration;

pub type RpcResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug)]
pub struct RpcClient {
    url: String,
    calls: u64,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            calls: 0,
        }
    }

    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// Perform one JSON-RPC call.
    ///
    /// second backoff. A JSON-RPC error is a successful HTTP exchange and maps
    /// to `None`, also matching the collector.
    pub fn call(&mut self, method: &str, params: Value) -> RpcResult<Option<Value>> {
        self.call_with_policy(method, params, 60, false)
    }

    /// Collector variant: five-minute request timeout and JSON-RPC errors are
    /// fatal rather than mapped to `None`.
    pub fn call_strict(&mut self, method: &str, params: Value) -> RpcResult<Value> {
        self.call_with_policy(method, params, 300, true)?
            .ok_or_else(|| "Ethereum JSON-RPC response has no result".into())
    }

    fn call_with_policy(
        &mut self,
        method: &str,
        params: Value,
        timeout_seconds: u64,
        strict_errors: bool,
    ) -> RpcResult<Option<Value>> {
        let payload = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }))?;
        for attempt in 0..4 {
            let output = Command::new("curl")
                .args([
                    "--silent",
                    "--show-error",
                    "--fail-with-body",
                    "--max-time",
                    &timeout_seconds.to_string(),
                    "--header",
                    "Content-Type: application/json",
                    "--data-binary",
                    &payload,
                    &self.url,
                ])
                .output()?;
            if output.status.success() {
                let body: Value = serde_json::from_slice(&output.stdout)?;
                self.calls += 1;
                if strict_errors {
                    if let Some(error) = body.get("error") {
                        return Err(format!("Ethereum JSON-RPC error: {error}").into());
                    }
                    return Ok(Some(body.get("result").cloned().unwrap_or(Value::Null)));
                }
                return Ok((body.get("error").is_none())
                    .then(|| body.get("result").cloned().unwrap_or(Value::Null)));
            }
            if attempt == 3 {
                let detail = String::from_utf8_lossy(&output.stderr);
                return Err(
                    format!("Ethereum JSON-RPC transport failed: {}", detail.trim()).into(),
                );
            }
            thread::sleep(Duration::from_secs(1 << attempt));
        }
        unreachable!("four-attempt RPC loop always returns")
    }
}
