//! Mutually authenticated production endpoint for one proof/FROST participant.

use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use qomm_transport::node_service::{
    certificate_fingerprint, load_owner_private_key, os_installation_boundary_id,
};
use qomm_transport::proof_party::{
    encode_bounded_response, read_bounded_request_line, ProofParty, ProofPartyConfig, ProofRequest,
    ProofResponse,
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const MAX_CONNECTIONS: usize = 64;
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Release);
}

#[derive(Deserialize)]
struct Config {
    deployment_id: String,
    node: u16,
    host: String,
    port: u16,
    certificate: PathBuf,
    private_key: PathBuf,
    ca_certificate: PathBuf,
    coordinator_certificate: PathBuf,
    allowed_root: PathBuf,
    state_file: PathBuf,
    state_passphrase_file: PathBuf,
    n_mm: usize,
    #[serde(default = "default_proof_parties")]
    n_parties: usize,
    threshold: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    complete_quote_proof: bool,
    #[serde(default = "default_quote_eligibility_bits")]
    quote_eligibility_bits: usize,
    #[serde(default = "default_quote_span_bits")]
    quote_span_bits: usize,
    /// Hex-encoded Ed25519 receipt key pinned by DeFMI governance.
    trusted_defmi_receipt_public: String,
    #[serde(default)]
    allow_health_signing: bool,
    idle_timeout_seconds: Option<u64>,
}

#[derive(Clone)]
struct RuntimeHealth {
    deployment_id: String,
    boot_id: [u8; 32],
    os_installation_id: [u8; 32],
}

fn default_proof_parties() -> usize {
    7
}

fn default_quote_eligibility_bits() -> usize {
    34
}

fn default_quote_span_bits() -> usize {
    32
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn certificate_der(path: &Path) -> Result<Vec<u8>, String> {
    let raw = fs::read(path).map_err(|error| error.to_string())?;
    let certificate = X509::from_der(&raw)
        .or_else(|_| X509::from_pem(&raw))
        .map_err(|error| error.to_string())?;
    certificate.to_der().map_err(|error| error.to_string())
}

fn private_secret(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!("proof-party state passphrase cannot be opened safely: {error}")
        })?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    // SAFETY: geteuid has no preconditions and does not expose secret data.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != effective_uid
        || metadata.len() > 4096
    {
        return Err(
            "proof-party state passphrase must be a bounded owner-only regular file owned by the service user"
                .into(),
        );
    }
    let mut value = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut value)
        .map_err(|error| error.to_string())?;
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        value.pop();
    }
    if !(16..=4096).contains(&value.len()) {
        return Err("proof-party state passphrase has an invalid length".into());
    }
    Ok(value)
}

fn public_key(value: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|_| "trusted DeFMI receipt key must be 32-byte hex".to_string())?
        .try_into()
        .map_err(|_| "trusted DeFMI receipt key must be 32-byte hex".to_string())
}

fn tls_acceptor(config: &Config, base: &Path) -> Result<SslAcceptor, String> {
    let private_key = load_owner_private_key(resolve(base, &config.private_key))?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .map_err(|error| error.to_string())?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| error.to_string())?;
    builder
        .set_certificate_chain_file(resolve(base, &config.certificate))
        .map_err(|error| error.to_string())?;
    builder
        .set_private_key(&private_key)
        .map_err(|error| error.to_string())?;
    builder
        .set_ca_file(resolve(base, &config.ca_certificate))
        .map_err(|error| error.to_string())?;
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    builder
        .check_private_key()
        .map_err(|error| error.to_string())?;
    Ok(builder.build())
}

fn serve_connection(
    stream: TcpStream,
    acceptor: Arc<SslAcceptor>,
    coordinator_fingerprint: String,
    party: Arc<Mutex<ProofParty>>,
    runtime: Arc<RuntimeHealth>,
    idle_timeout: Duration,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(idle_timeout))
        .and_then(|_| stream.set_write_timeout(Some(idle_timeout)))
        .map_err(|error| error.to_string())?;
    let stream = acceptor.accept(stream).map_err(|error| error.to_string())?;
    let peer = stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| "proof-party peer omitted its certificate".to_string())?;
    if certificate_fingerprint(&peer.to_der().map_err(|error| error.to_string())?)
        != coordinator_fingerprint
    {
        return Err("proof-party rejected a non-coordinator certificate".into());
    }
    let mut stream = BufReader::new(stream);
    loop {
        let Some(line) = read_bounded_request_line(&mut stream)? else {
            return Ok(());
        };
        let request: ProofRequest = serde_json::from_slice(&line)
            .map_err(|_| "proof-party request is not valid JSON".to_string())?;
        let is_health = request.method == "health";
        let id = request.id;
        let requested_deployment = request.params.get("deployment_id").and_then(Value::as_str);
        let mut response: ProofResponse =
            if is_health && requested_deployment != Some(runtime.deployment_id.as_str()) {
                ProofResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some("proof-party health deployment id does not match".into()),
                }
            } else {
                party
                    .lock()
                    .map_err(|_| "proof-party state lock is poisoned".to_string())?
                    .handle(request)
            };
        if is_health && response.ok {
            let object = response
                .result
                .as_mut()
                .and_then(Value::as_object_mut)
                .ok_or_else(|| "proof-party health response is not an object".to_string())?;
            object.insert(
                "deployment_id".into(),
                Value::String(runtime.deployment_id.clone()),
            );
            object.insert(
                "boot_id".into(),
                Value::String(hex::encode(runtime.boot_id)),
            );
            object.insert(
                "os_installation_id".into(),
                Value::String(hex::encode(runtime.os_installation_id)),
            );
        }
        let encoded = encode_bounded_response(&response)?;
        stream
            .get_mut()
            .write_all(&encoded)
            .and_then(|_| stream.get_mut().write_all(b"\n"))
            .and_then(|_| stream.get_mut().flush())
            .map_err(|error| error.to_string())?;
    }
}

fn run(config_path: &Path) -> Result<(), String> {
    let config: Config =
        serde_json::from_slice(&fs::read(config_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    let os_installation_id = os_installation_boundary_id(&config.deployment_id)?;
    let mut boot_id = [0_u8; 32];
    OsRng.fill_bytes(&mut boot_id);
    let runtime = Arc::new(RuntimeHealth {
        deployment_id: config.deployment_id.clone(),
        boot_id,
        os_installation_id,
    });
    let allowed_root = resolve(base, &config.allowed_root);
    let party = ProofParty::new(ProofPartyConfig {
        node: config.node,
        allowed_root,
        state_file: resolve(base, &config.state_file),
        state_passphrase: private_secret(&resolve(base, &config.state_passphrase_file))?,
        n_mm: config.n_mm,
        n_parties: config.n_parties,
        threshold: config.threshold,
        amount_bits: config.amount_bits,
        price_bits: config.price_bits,
        remainder_bits: config.remainder_bits,
        complete_quote_proof: config.complete_quote_proof,
        quote_eligibility_bits: config.quote_eligibility_bits,
        quote_span_bits: config.quote_span_bits,
        trusted_defmi_receipt_public: Some(public_key(&config.trusted_defmi_receipt_public)?),
        allow_health_signing: config.allow_health_signing,
    })?;
    let coordinator_fingerprint = certificate_fingerprint(&certificate_der(&resolve(
        base,
        &config.coordinator_certificate,
    ))?);
    let acceptor = Arc::new(tls_acceptor(&config, base)?);
    let listener = TcpListener::bind((config.host.as_str(), config.port))
        .map_err(|error| error.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let port = listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    let proof_instance_id = party.instance_id();
    let party = Arc::new(Mutex::new(party));
    let timeout = Duration::from_secs(config.idle_timeout_seconds.unwrap_or(30));
    // SAFETY: handlers only set one lock-free atomic flag.
    unsafe {
        libc::signal(
            libc::SIGINT,
            request_stop as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            request_stop as *const () as libc::sighandler_t,
        );
    }
    println!(
        "{}",
        json!({
            "status": "ready",
            "deployment_id": config.deployment_id,
            "node": config.node,
            "host": config.host,
            "port": port,
            "instance_id": hex::encode(proof_instance_id),
            "os_installation_id": hex::encode(runtime.os_installation_id),
            "complete_quote_proof": config.complete_quote_proof,
        })
    );
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while !STOP.load(Ordering::Acquire) {
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                let worker = workers.swap_remove(index);
                let _ = worker.join();
            } else {
                index += 1;
            }
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if workers.len() >= MAX_CONNECTIONS {
                    eprintln!("proof-party rejected a connection above its fixed worker bound");
                    drop(stream);
                    continue;
                }
                let acceptor = Arc::clone(&acceptor);
                let party = Arc::clone(&party);
                let runtime = Arc::clone(&runtime);
                let coordinator = coordinator_fingerprint.clone();
                workers.push(thread::spawn(move || {
                    if let Err(error) =
                        serve_connection(stream, acceptor, coordinator, party, runtime, timeout)
                    {
                        eprintln!("proof-party connection failed: {error}");
                    }
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = arguments
        .iter()
        .position(|argument| argument == "--config")
        .and_then(|position| arguments.get(position + 1))
        .ok_or_else(|| "usage: serve_proof_party --config PATH".to_string())
        .and_then(|path| run(Path::new(path)));
    if let Err(error) = result {
        eprintln!("serve_proof_party failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use qomm_transport::key_management::{
        create_ca, issue_mutual_tls_certificate, write_tls_bundle,
    };
    use qomm_transport::node_service::client_ssl_context;
    use qomm_transport::proof_client::ProofPartyTlsClient;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[test]
    fn proof_state_secret_is_owner_only_bounded_and_never_follows_links() {
        let root = TempDir::new().unwrap();
        let secret = root.path().join("secret");
        fs::write(&secret, b"0123456789abcdef0123456789abcdef\n").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            private_secret(&secret).unwrap(),
            b"0123456789abcdef0123456789abcdef"
        );

        let linked = root.path().join("linked");
        symlink(&secret, &linked).unwrap();
        assert!(private_secret(&linked).unwrap_err().contains("safely"));

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(private_secret(&secret).unwrap_err().contains("owner-only"));

        let oversized = root.path().join("oversized");
        fs::write(&oversized, vec![b'x'; 4097]).unwrap();
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_secret(&oversized).unwrap_err().contains("bounded"));
    }

    #[test]
    fn real_mutual_tls_proof_service_returns_deployment_bound_health() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (ca_key, ca_cert) = create_ca("proof-test-ca", 30).unwrap();
        let (node_key, node_cert) = issue_mutual_tls_certificate(
            &ca_key,
            &ca_cert,
            "proof-node",
            &["proof-node"],
            &["127.0.0.1"],
            30,
        )
        .unwrap();
        let (coordinator_key, coordinator_cert) = issue_mutual_tls_certificate(
            &ca_key,
            &ca_cert,
            "coordinator",
            &["coordinator"],
            &["127.0.0.1"],
            30,
        )
        .unwrap();
        let (node_key_path, node_cert_path, node_ca_path) = write_tls_bundle(
            root.path().join("node-pki"),
            "proof-node",
            &node_key,
            &node_cert,
            &ca_cert,
        )
        .unwrap();
        let (coordinator_key_path, coordinator_cert_path, coordinator_ca_path) = write_tls_bundle(
            root.path().join("coordinator-pki"),
            "coordinator",
            &coordinator_key,
            &coordinator_cert,
            &ca_cert,
        )
        .unwrap();
        let receipt_key = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let config = Config {
            deployment_id: "proof-tls-test".into(),
            node: 0,
            host: "127.0.0.1".into(),
            port: 0,
            certificate: node_cert_path,
            private_key: node_key_path,
            ca_certificate: node_ca_path,
            coordinator_certificate: coordinator_cert_path.clone(),
            allowed_root: root.path().to_path_buf(),
            state_file: root.path().join("proof-state.qps"),
            state_passphrase_file: root.path().join("unused"),
            n_mm: 4,
            n_parties: 7,
            threshold: 2,
            amount_bits: 16,
            price_bits: 32,
            remainder_bits: 32,
            complete_quote_proof: true,
            quote_eligibility_bits: 34,
            quote_span_bits: 32,
            trusted_defmi_receipt_public: hex::encode(receipt_key),
            allow_health_signing: false,
            idle_timeout_seconds: Some(2),
        };
        let party = ProofParty::new(ProofPartyConfig {
            node: 0,
            allowed_root: root.path().to_path_buf(),
            state_file: root.path().join("proof-state.qps"),
            state_passphrase: vec![0x55; 32],
            n_mm: 4,
            n_parties: 7,
            threshold: 2,
            amount_bits: 16,
            price_bits: 32,
            remainder_bits: 32,
            complete_quote_proof: true,
            quote_eligibility_bits: 34,
            quote_span_bits: 32,
            trusted_defmi_receipt_public: Some(receipt_key),
            allow_health_signing: false,
        })
        .unwrap();
        let instance_id = hex::encode(party.instance_id());
        let acceptor = Arc::new(tls_acceptor(&config, Path::new("/")).unwrap());
        let coordinator_fingerprint =
            certificate_fingerprint(&certificate_der(&coordinator_cert_path).unwrap());
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let runtime = Arc::new(RuntimeHealth {
            deployment_id: config.deployment_id.clone(),
            boot_id: [0x11; 32],
            os_installation_id: [0x22; 32],
        });
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(
                stream,
                acceptor,
                coordinator_fingerprint,
                Arc::new(Mutex::new(party)),
                runtime,
                Duration::from_secs(2),
            )
            .unwrap();
        });

        let tls = client_ssl_context(
            coordinator_cert_path,
            coordinator_key_path,
            coordinator_ca_path,
        )
        .unwrap();
        let mut client =
            ProofPartyTlsClient::new("127.0.0.1", port, tls, "proof-node", Duration::from_secs(2));
        let health = client
            .call("health", json!({"deployment_id": "proof-tls-test"}))
            .unwrap();
        assert_eq!(health["deployment_id"], "proof-tls-test");
        assert_eq!(health["instance_id"], instance_id);
        assert_eq!(health["complete_quote_proof"], true);
        client.close();
        worker.join().unwrap();
    }
}
