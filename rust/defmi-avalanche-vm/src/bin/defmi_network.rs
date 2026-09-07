//! Container supervisor for a five-validator local DeFMI Avalanche network.
//!
//! Avalanche Network Runner owns the five unmodified AvalancheGo processes.
//! This Rust supervisor installs the QOMM VM plugin, discovers the generated
//! chain endpoint, and exposes one stable Docker-network JSON-RPC proxy plus a
//! topology manifest.  It is infrastructure glue, not a replacement consensus
//! or an in-memory ledger.

use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_HTTP_BYTES: usize = 4 << 20;
const VALIDATORS: usize = 5;
const LIVE_SNAPSHOT: &str = "defmi-live";

#[derive(Clone, Debug)]
struct Options {
    runner: PathBuf,
    avalanchego: PathBuf,
    vm: PathBuf,
    genesis_config: PathBuf,
    state_root: PathBuf,
    runner_port: u16,
    runner_gateway_port: u16,
    proxy_host: String,
    proxy_port: u16,
}

fn argument(arguments: &[String], name: &str) -> Result<String, String> {
    let position = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| format!("missing {name}"))?;
    arguments
        .get(position + 1)
        .cloned()
        .ok_or_else(|| format!("{name} requires a value"))
}

impl Options {
    fn parse() -> Result<Self, String> {
        let arguments = std::env::args().skip(1).collect::<Vec<_>>();
        let port = |name: &str| -> Result<u16, String> {
            argument(&arguments, name)?
                .parse()
                .map_err(|_| format!("{name} must be an unsigned 16-bit integer"))
        };
        Ok(Self {
            runner: PathBuf::from(argument(&arguments, "--runner")?),
            avalanchego: PathBuf::from(argument(&arguments, "--avalanchego")?),
            vm: PathBuf::from(argument(&arguments, "--vm")?),
            genesis_config: PathBuf::from(argument(&arguments, "--genesis-config")?),
            state_root: PathBuf::from(argument(&arguments, "--state-root")?),
            runner_port: port("--runner-port")?,
            runner_gateway_port: port("--runner-gateway-port")?,
            proxy_host: argument(&arguments, "--proxy-host")?,
            proxy_port: port("--proxy-port")?,
        })
    }

    fn validate(&self) -> Result<(), String> {
        for (name, path) in [
            ("network runner", &self.runner),
            ("AvalancheGo", &self.avalanchego),
            ("QOMM VM", &self.vm),
        ] {
            let metadata = path
                .metadata()
                .map_err(|error| format!("{name} is unavailable: {error}"))?;
            if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
                return Err(format!("{name} is not executable: {}", path.display()));
            }
        }
        if !self.genesis_config.is_file()
            || self.runner_port == 0
            || self.runner_gateway_port == 0
            || self.proxy_port == 0
            || self.runner_port == self.runner_gateway_port
            || self.runner_port == self.proxy_port
            || self.runner_gateway_port == self.proxy_port
        {
            return Err("DeFMI network paths or ports are invalid".into());
        }
        Ok(())
    }
}

struct RunnerGuard {
    binary: PathBuf,
    endpoint: String,
    child: Child,
}

impl Drop for RunnerGuard {
    fn drop(&mut self) {
        let _ = Command::new(&self.binary)
            .args(["control", "stop"])
            .arg(format!("--endpoint={}", self.endpoint))
            .arg("--request-timeout=30s")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command_output(mut command: Command, description: &str) -> Result<String, String> {
    let output = command.output().map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "{description} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn control(options: &Options, arguments: &[&str]) -> Result<String, String> {
    let mut command = Command::new(&options.runner);
    command.args(["control"]);
    command.args(arguments);
    command.arg(format!("--endpoint=localhost:{}", options.runner_port));
    command_output(command, "Avalanche Network Runner control request")
}

fn strip_ansi(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut bytes = value.bytes().peekable();
    while let Some(byte) = bytes.next() {
        if byte == 0x1b && bytes.peek() == Some(&b'[') {
            bytes.next();
            for next in bytes.by_ref() {
                if (0x40..=0x7e).contains(&next) {
                    break;
                }
            }
        } else {
            output.push(char::from(byte));
        }
    }
    output
}

fn discover(options: &Options) -> Result<(String, Vec<String>), String> {
    let blockchains = strip_ansi(&control(options, &["list-blockchains"])?);
    let chain_id = blockchains
        .lines()
        .find_map(|line| {
            line.split_once("Blockchain ID: ")
                .map(|value| value.1.trim())
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "local DeFMI chain id was not reported".to_string())?
        .to_string();
    let uri_output = strip_ansi(&control(options, &["uris"])?);
    let uri_line = uri_output
        .lines()
        .find_map(|line| line.split_once("URIs: [").map(|value| value.1))
        .and_then(|value| value.split_once(']').map(|part| part.0))
        .ok_or_else(|| "local DeFMI validator URIs were not reported".to_string())?;
    let uris = uri_line
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if uris.len() != VALIDATORS {
        return Err(format!(
            "local DeFMI expected {VALIDATORS} validator URIs, got {}",
            uris.len()
        ));
    }
    Ok((chain_id, uris))
}

fn run() -> Result<(), String> {
    let options = Options::parse()?;
    options.validate()?;
    fs::create_dir_all(&options.state_root).map_err(|error| error.to_string())?;
    let plugin_dir = options.state_root.join("plugins");
    let data_dir = options.state_root.join("data");
    let logs_dir = options.state_root.join("logs");
    let snapshots_dir = options.state_root.join("snapshots");
    fs::create_dir_all(&plugin_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(&logs_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(&snapshots_dir).map_err(|error| error.to_string())?;
    let vm_id = {
        let mut command = Command::new(&options.vm);
        command.arg("vmid");
        command_output(command, "QOMM VM id query")?
            .trim()
            .to_string()
    };
    if vm_id.is_empty() || vm_id.contains('/') {
        return Err("QOMM VM returned an invalid VM id".into());
    }
    let plugin = plugin_dir.join(&vm_id);
    fs::copy(&options.vm, &plugin).map_err(|error| error.to_string())?;
    fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755))
        .map_err(|error| error.to_string())?;
    let genesis = options.state_root.join("genesis.bin");
    let mut genesis_command = Command::new(&options.vm);
    genesis_command
        .arg("genesis")
        .arg("--config")
        .arg(&options.genesis_config)
        .arg("--out")
        .arg(&genesis);
    command_output(genesis_command, "QOMM genesis compilation")?;
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs_dir.join("network-runner.log"))
        .map_err(|error| error.to_string())?;
    let stderr = stdout.try_clone().map_err(|error| error.to_string())?;
    let child = Command::new(&options.runner)
        .arg("server")
        .arg(format!("--port=:{}", options.runner_port))
        .arg(format!(
            "--grpc-gateway-port=:{}",
            options.runner_gateway_port
        ))
        .arg(format!("--log-dir={}", logs_dir.display()))
        .arg(format!("--snapshots-dir={}", snapshots_dir.display()))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("network runner did not start: {error}"))?;
    let endpoint = format!("localhost:{}", options.runner_port);
    let _guard = RunnerGuard {
        binary: options.runner.clone(),
        endpoint,
        child,
    };
    let ready_started = Instant::now();
    loop {
        if control(&options, &["rpc_version"]).is_ok() {
            break;
        }
        if ready_started.elapsed() > Duration::from_secs(30) {
            return Err(format!(
                "network runner did not become ready; inspect {}",
                logs_dir.join("network-runner.log").display()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
    // Reserve the stable Docker-facing endpoint before Network Runner assigns
    // validator API ports.  Otherwise node1 can take `proxy_port` (9650 by
    // default) while the port is still free, and the proxy only discovers the
    // collision after the five-validator network has become healthy.
    let listener = TcpListener::bind((options.proxy_host.as_str(), options.proxy_port))
        .map_err(|error| error.to_string())?;
    // Network Runner stores named snapshots as `anr-snapshot-<name>` beneath
    // the configured snapshots directory.  Detect that canonical directory so
    // a container restart resumes the accepted ledger instead of attempting a
    // new genesis over the persisted validator databases.
    let live_snapshot_dir = snapshots_dir.join(format!("anr-snapshot-{LIVE_SNAPSHOT}"));
    if live_snapshot_dir.join("network.json").is_file() {
        control(
            &options,
            &[
                "load-snapshot",
                LIVE_SNAPSHOT,
                "--request-timeout=5m",
                "--in-place",
                &format!("--avalanchego-path={}", options.avalanchego.display()),
                &format!("--plugin-dir={}", plugin_dir.display()),
                "--reassign-ports-if-used",
            ],
        )?;
    } else {
        let spec = serde_json::to_string(&vec![json!({
            "vm_name": "defmivm",
            "genesis": genesis,
        })])
        .map_err(|error| error.to_string())?;
        control(
            &options,
            &[
                "start",
                "--request-timeout=5m",
                &format!("--avalanchego-path={}", options.avalanchego.display()),
                &format!("--plugin-dir={}", plugin_dir.display()),
                &format!("--root-data-dir={}", data_dir.display()),
                "--network-id=1337",
                "--num-nodes=5",
                "--dynamic-ports",
                "--reassign-ports-if-used",
                &format!("--blockchain-specs={spec}"),
            ],
        )?;
        control(&options, &["wait-for-healthy", "--request-timeout=5m"])?;
        control(
            &options,
            &["save-snapshot", LIVE_SNAPSHOT, "--request-timeout=5m"],
        )?;
        control(
            &options,
            &[
                "load-snapshot",
                LIVE_SNAPSHOT,
                "--request-timeout=5m",
                "--in-place",
                &format!("--avalanchego-path={}", options.avalanchego.display()),
                &format!("--plugin-dir={}", plugin_dir.display()),
                "--reassign-ports-if-used",
            ],
        )?;
    }
    control(&options, &["wait-for-healthy", "--request-timeout=5m"])?;
    let (chain_id, uris) = discover(&options)?;
    let primary = format!("{}/ext/bc/{chain_id}", uris[0].trim_end_matches('/'));
    let manifest = Arc::new(json!({
        "ok": true,
        "service": "defmi-network",
        "network_id": 1337,
        "chain_id": chain_id,
        "rpc_path": "/rpc",
        "validator_count": VALIDATORS,
        "validators": (0..VALIDATORS).map(|index| json!({
            "id": format!("defmi-validator-{index}"),
            "status": "healthy",
        })).collect::<Vec<_>>(),
        "consensus": "AvalancheGo",
        "vm": "qomm-avalanche-vm",
        "evm": false,
    }));
    let upstream = Arc::new(primary);
    println!(
        "DeFMI five-validator network ready at http://{}/rpc, chain {}",
        listener.local_addr().map_err(|error| error.to_string())?,
        manifest
            .get("chain_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let upstream = Arc::clone(&upstream);
                let manifest = Arc::clone(&manifest);
                thread::spawn(move || {
                    if let Err(error) = handle(stream, &upstream, &manifest) {
                        eprintln!("DeFMI proxy request failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("DeFMI proxy accept failed: {error}"),
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, upstream: &str, manifest: &Value) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(190)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(190))))
        .map_err(|error| error.to_string())?;
    let (method, path, body) = read_request(&mut stream)?;
    let response = match (method.as_str(), path.as_str()) {
        ("GET", "/health") | ("GET", "/manifest") => json_response("200 OK", manifest),
        ("POST", "/rpc") => proxy(upstream, &body)?,
        _ => json_response(
            "404 Not Found",
            &json!({"error":"no such DeFMI network operation"}),
        ),
    };
    stream
        .write_all(&response)
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())
}

fn parse_http_url(value: &str) -> Result<(String, String), String> {
    let rest = value
        .strip_prefix("http://")
        .ok_or_else(|| "Avalanche node URI must use http://".to_string())?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || !authority.contains(':') {
        return Err("Avalanche node URI has no host and port".into());
    }
    Ok((authority.to_string(), format!("/{path}")))
}

fn proxy(upstream: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    if body.is_empty() || body.len() > MAX_HTTP_BYTES {
        return Ok(json_response(
            "400 Bad Request",
            &json!({"error":"JSON-RPC body is empty or too large"}),
        ));
    }
    let _: Value = serde_json::from_slice(body)
        .map_err(|_| "DeFMI JSON-RPC proxy body is not JSON".to_string())?;
    let (authority, path) = parse_http_url(upstream)?;
    let address = authority
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "Avalanche primary RPC did not resolve".to_string())?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(185)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(185))))
        .map_err(|error| error.to_string())?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.flush())
        .map_err(|error| error.to_string())?;
    let mut raw = Vec::new();
    Read::by_ref(&mut stream)
        .take((MAX_HTTP_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() > MAX_HTTP_BYTES {
        return Err("Avalanche JSON-RPC response exceeded its fixed bound".into());
    }
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "Avalanche JSON-RPC response is malformed".to_string())?;
    let head =
        std::str::from_utf8(&raw[..split]).map_err(|_| "Avalanche HTTP headers are not UTF-8")?;
    let mut headers = head.lines();
    let status = headers.next().unwrap_or_default();
    let chunked = headers.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let raw_body = &raw[split + 4..];
    let body = if chunked {
        decode_chunked_response(raw_body)?
    } else {
        raw_body.to_vec()
    };
    if body.len() > MAX_HTTP_BYTES {
        return Err("Avalanche JSON-RPC response body exceeded its fixed bound".into());
    }
    let response_status = if status.contains(" 200 ") {
        "200 OK"
    } else {
        "502 Bad Gateway"
    };
    let mut response = format!(
        "HTTP/1.1 {response_status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);
    Ok(response)
}

fn decode_chunked_response(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "Avalanche JSON-RPC returned malformed chunked HTTP".to_string())?;
        let length = std::str::from_utf8(&body[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|length| usize::from_str_radix(length.trim(), 16).ok())
            .ok_or_else(|| "Avalanche JSON-RPC returned malformed chunked HTTP".to_string())?;
        body = &body[line_end + 2..];
        if length == 0 {
            return Ok(decoded);
        }
        if body.len() < length + 2 || &body[length..length + 2] != b"\r\n" {
            return Err("Avalanche JSON-RPC returned malformed chunked HTTP".into());
        }
        decoded.extend_from_slice(&body[..length]);
        if decoded.len() > MAX_HTTP_BYTES {
            return Err("Avalanche JSON-RPC response body exceeded its fixed bound".into());
        }
        body = &body[length + 2..];
    }
}

fn read_request(stream: &mut TcpStream) -> Result<(String, String, Vec<u8>), String> {
    let mut raw = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("HTTP request ended before its headers".into());
        }
        raw.extend_from_slice(&chunk[..count]);
        if raw.len() > MAX_HTTP_BYTES {
            return Err("HTTP request exceeded its fixed bound".into());
        }
        if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&raw[..header_end]).map_err(|_| "HTTP headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let request = lines
        .next()
        .ok_or_else(|| "HTTP request line is absent".to_string())?;
    let mut fields = request.split_whitespace();
    let method = fields.next().unwrap_or_default().to_string();
    let path = fields.next().unwrap_or_default().to_string();
    if fields.next().is_none() || path.contains('?') {
        return Err("HTTP request line is malformed".into());
    }
    let mut length = 0_usize;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "HTTP header is malformed".to_string())?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("chunked HTTP requests are not accepted".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = value
                .trim()
                .parse()
                .map_err(|_| "Content-Length is invalid".to_string())?;
        }
    }
    if length > MAX_HTTP_BYTES || raw.len().saturating_sub(header_end) > length {
        return Err("HTTP body length is outside its fixed bound".into());
    }
    while raw.len().saturating_sub(header_end) < length {
        let remaining = length - raw.len().saturating_sub(header_end);
        let mut chunk = vec![0_u8; remaining.min(4096)];
        stream
            .read_exact(&mut chunk)
            .map_err(|error| error.to_string())?;
        raw.extend_from_slice(&chunk);
    }
    Ok((method, path, raw[header_end..].to_vec()))
}

fn json_response(status: &str, value: &Value) -> Vec<u8> {
    let body =
        serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"serialization\"}".to_vec());
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend(body);
    response
}

fn main() {
    if let Err(error) = run() {
        eprintln!("defmi-network failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::decode_chunked_response;

    #[test]
    fn decodes_chunked_avalanche_json_with_extensions_and_trailers() {
        let encoded = b"4;name=value\r\n{\"ok\r\n4\r\n\":1}\r\n0\r\nX-Trace: done\r\n\r\n";
        assert_eq!(decode_chunked_response(encoded).unwrap(), b"{\"ok\":1}");
    }

    #[test]
    fn rejects_a_truncated_chunk() {
        assert!(decode_chunked_response(b"4\r\n{}\r\n0\r\n\r\n").is_err());
    }
}
