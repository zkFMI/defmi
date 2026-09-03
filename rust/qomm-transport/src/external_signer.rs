//! Process-isolated Ed25519 signing boundary for HSM/KMS adapters.
//!
//! QOMM sends only an already domain-separated message to a fixed executable
//! and verifies the returned signature against a pinned public key. The
//! executable may be backed by PKCS#11, a cloud KMS or a local acceptance
//! emulator; the application process never receives private-key bytes.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PROTOCOL_VERSION: u8 = 1;
pub const MAX_EXTERNAL_SIGN_MESSAGE: usize = 64 << 10;
pub const MAX_EXTERNAL_SIGN_REQUEST: u64 = 96 << 10;
pub const MAX_EXTERNAL_SIGN_RESPONSE: u64 = 4 << 10;

pub trait Ed25519MessageSigner {
    fn key_id(&self) -> &str;
    fn verifying_key(&self) -> VerifyingKey;
    fn sign_message(&self, message: &[u8]) -> Result<Signature, String>;
}

impl Ed25519MessageSigner for SigningKey {
    fn key_id(&self) -> &str {
        "in-process-acceptance-key"
    }

    fn verifying_key(&self) -> VerifyingKey {
        SigningKey::verifying_key(self)
    }

    fn sign_message(&self, message: &[u8]) -> Result<Signature, String> {
        Ok(self.sign(message))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSignRequest {
    pub version: u8,
    pub key_id: String,
    pub message: String,
}

impl ExternalSignRequest {
    pub fn new(key_id: &str, message: &[u8]) -> Result<Self, String> {
        if key_id.is_empty()
            || key_id.len() > 256
            || message.is_empty()
            || message.len() > MAX_EXTERNAL_SIGN_MESSAGE
        {
            return Err("external signing request exceeds its bounds".into());
        }
        Ok(Self {
            version: PROTOCOL_VERSION,
            key_id: key_id.into(),
            message: BASE64.encode(message),
        })
    }

    pub fn decode_message(&self) -> Result<Vec<u8>, String> {
        if self.version != PROTOCOL_VERSION || self.key_id.is_empty() || self.key_id.len() > 256 {
            return Err("unsupported external signing request".into());
        }
        let message = BASE64
            .decode(&self.message)
            .map_err(|_| "external signing message is not base64".to_string())?;
        if message.is_empty() || message.len() > MAX_EXTERNAL_SIGN_MESSAGE {
            return Err("external signing message exceeds its bounds".into());
        }
        Ok(message)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSignResponse {
    pub version: u8,
    pub key_id: String,
    pub signature: String,
}

impl ExternalSignResponse {
    pub fn new(key_id: &str, signature: &Signature) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            key_id: key_id.into(),
            signature: hex::encode(signature.to_bytes()),
        }
    }

    fn signature(&self, expected_key_id: &str) -> Result<Signature, String> {
        if self.version != PROTOCOL_VERSION || self.key_id != expected_key_id {
            return Err("external signer returned another protocol version or key".into());
        }
        let raw: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| "external signer signature is not hexadecimal".to_string())?
            .try_into()
            .map_err(|_| "external signer signature is not 64 bytes".to_string())?;
        Ok(Signature::from_bytes(&raw))
    }
}

#[derive(Clone, Debug)]
pub struct CommandEd25519Signer {
    executable: PathBuf,
    fixed_arguments: Vec<String>,
    key_id: String,
    public_key: VerifyingKey,
    timeout: Duration,
}

impl CommandEd25519Signer {
    pub fn new(
        executable: impl Into<PathBuf>,
        fixed_arguments: Vec<String>,
        key_id: impl Into<String>,
        public_key: VerifyingKey,
        timeout: Duration,
    ) -> Result<Self, String> {
        let executable = executable.into();
        let key_id = key_id.into();
        if !executable.is_absolute()
            || key_id.is_empty()
            || key_id.len() > 256
            || fixed_arguments.len() > 32
            || fixed_arguments
                .iter()
                .any(|argument| argument.len() > 4096 || argument.contains('\0'))
            || timeout < Duration::from_millis(10)
            || timeout > Duration::from_secs(30)
        {
            return Err("external signer configuration is invalid".into());
        }
        let metadata = fs::symlink_metadata(&executable).map_err(|error| error.to_string())?;
        let mode = metadata.permissions().mode();
        if !metadata.file_type().is_file() || mode & 0o111 == 0 || mode & 0o022 != 0 {
            return Err("external signer must be a non-writable executable regular file".into());
        }
        Ok(Self {
            executable,
            fixed_arguments,
            key_id,
            public_key,
            timeout,
        })
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

impl Ed25519MessageSigner for CommandEd25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.public_key
    }

    fn sign_message(&self, message: &[u8]) -> Result<Signature, String> {
        let request = serde_json::to_vec(&ExternalSignRequest::new(&self.key_id, message)?)
            .map_err(|error| error.to_string())?;
        if request.len() as u64 > MAX_EXTERNAL_SIGN_REQUEST {
            return Err("serialized external signing request exceeds its bound".into());
        }
        let mut child = Command::new(&self.executable)
            .args(&self.fixed_arguments)
            .arg("--sign")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("external signer could not start: {error}"))?;
        let mut request_stream = child
            .stdin
            .take()
            .ok_or_else(|| "external signer has no request stream".to_string())?;
        let response_stream = child
            .stdout
            .take()
            .ok_or_else(|| "external signer has no response stream".to_string())?;

        // Both pipe directions run outside the supervising thread. Otherwise a
        // signer that never reads stdin, or writes until stdout fills, can block
        // before the timeout loop is reached. Killing the child closes both
        // pipes, so the workers terminate and can be joined without leaking a
        // background task.
        let writer = thread::spawn(move || {
            request_stream
                .write_all(&request)
                .map_err(|error| format!("external signer request failed: {error}"))
        });
        let reader = thread::spawn(move || {
            let mut output = Vec::new();
            response_stream
                .take(MAX_EXTERNAL_SIGN_RESPONSE + 1)
                .read_to_end(&mut output)
                .map_err(|error| error.to_string())?;
            Ok::<Vec<u8>, String>(output)
        });
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                break status;
            }
            if started.elapsed() >= self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                let _ = reader.join();
                return Err("external signer timed out".into());
            }
            thread::sleep(Duration::from_millis(5));
        };
        writer
            .join()
            .map_err(|_| "external signer request worker panicked".to_string())??;
        let output = reader
            .join()
            .map_err(|_| "external signer response worker panicked".to_string())??;
        if !status.success() {
            return Err("external signer rejected the request".into());
        }
        if output.is_empty() || output.len() as u64 > MAX_EXTERNAL_SIGN_RESPONSE {
            return Err("external signer response exceeds its bound".into());
        }
        let response: ExternalSignResponse = serde_json::from_slice(&output)
            .map_err(|_| "external signer response is malformed".to_string())?;
        let signature = response.signature(&self.key_id)?;
        self.public_key
            .verify(message, &signature)
            .map_err(|_| "external signer returned an invalid signature".to_string())?;
        Ok(signature)
    }
}
