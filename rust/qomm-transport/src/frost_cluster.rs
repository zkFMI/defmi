//! Coordinator for a process-isolated FROST committee.
//!
//! The coordinator only relays authenticated public DKG packages,
//! commitments, and signature shares.  Every child keeps its identity, DKG
//! share, one-time nonce, and replay journal in its own encrypted state file.
//! This module is used by acceptance runners; production deployments expose
//! the same `ProofRequest` protocol over the mutually authenticated
//! `serve_proof_party` endpoint.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use qomm_zkpi::{frost, typed, typed_wire, wire as payment_wire, PartialInstruction, QuoteBinding};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::frost_coordinator;
use crate::mandate::{MakerPolicyMandate, TakerExecutionMandate};
use crate::proof_client::{ProofPartyRpc, ProofPartyTlsClient};
use crate::proof_party::{ProofRequest, ProofResponse};

const MAX_RESPONSE: usize = 8 << 20;
const MAX_REQUEST: usize = 8 << 20;

#[derive(Clone, Copy)]
pub enum ReserveMandateRef<'a> {
    Maker(&'a MakerPolicyMandate),
    Taker(&'a TakerExecutionMandate),
}

impl ReserveMandateRef<'_> {
    pub fn limit_price_commitment(self) -> [u8; 32] {
        match self {
            Self::Maker(_) => [0; 32],
            Self::Taker(value) => value.limit_price_commitment,
        }
    }

    fn public_params(&self) -> Result<Value, String> {
        match self {
            Self::Maker(value) => Ok(json!({
                "role": "maker",
                "mandate_unsigned": BASE64.encode(value.unsigned()?),
                "mandate_signature": hex::encode(value.signature.to_bytes()),
            })),
            Self::Taker(value) => Ok(json!({
                "role": "taker",
                "mandate_unsigned": BASE64.encode(value.unsigned()?),
                "mandate_signature": hex::encode(value.signature.to_bytes()),
            })),
        }
    }
}

struct ProofPartyChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl ProofPartyChild {
    fn spawn(executable: &Path, node: u16, root: &Path) -> Result<Self, String> {
        let node_state = root.join(format!("node-{node}"));
        fs::create_dir_all(&node_state).map_err(|error| error.to_string())?;
        fs::set_permissions(&node_state, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let mut child = Command::new(executable)
            .arg("--proof-party")
            .arg("--node")
            .arg(node.to_string())
            .arg("--proof-root")
            .arg(root)
            .arg("--proof-state")
            .arg(node_state.join("state.qps"))
            .arg("--proof-passphrase-file")
            .arg(node_state.join("passphrase.bin"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("failed to start reserve proof party {node}: {error}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "proof-party stdin was not created".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "proof-party stdout was not created".to_string())?;
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            next_id: 1,
        })
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| "proof-party request identifier is exhausted".to_string())?;
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| "proof-party process is already closed".to_string())?;
        let encoded = serde_json::to_vec(&ProofRequest {
            id,
            method: method.to_string(),
            params,
        })
        .map_err(|error| error.to_string())?;
        if encoded.len().saturating_add(1) > MAX_REQUEST {
            return Err("proof-party request exceeded its fixed bound".into());
        }
        stdin
            .write_all(&encoded)
            .and_then(|_| stdin.write_all(b"\n"))
            .map_err(|error| error.to_string())?;
        stdin.flush().map_err(|error| error.to_string())?;
        let line = ProofPartyTlsClient::read_bounded_line(&mut self.stdout)?;
        if line.len() > MAX_RESPONSE {
            return Err("proof-party response exceeded its fixed bound".into());
        }
        let response: ProofResponse =
            serde_json::from_slice(&line).map_err(|_| "proof-party returned invalid JSON")?;
        if response.id != id {
            return Err("proof-party response identifier does not match".into());
        }
        if !response.ok {
            return Err(response
                .error
                .unwrap_or_else(|| "proof-party rejected the request".into()));
        }
        response
            .result
            .ok_or_else(|| "proof-party success response has no result".into())
    }

    fn close(&mut self) -> Result<(), String> {
        self.stdin.take();
        let status = self.child.wait().map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("proof-party process exited with {status}"))
        }
    }
}

impl ProofPartyRpc for ProofPartyChild {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        ProofPartyChild::call(self, method, params)
    }
}

impl Drop for ProofPartyChild {
    fn drop(&mut self) {
        self.stdin.take();
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

pub struct StdioFrostCluster {
    root: PathBuf,
    parties: Vec<ProofPartyChild>,
    public: frost::keys::PublicKeyPackage,
    selected: Vec<usize>,
}

impl StdioFrostCluster {
    pub fn start(
        executable: impl AsRef<Path>,
        root: impl AsRef<Path>,
        session: [u8; 32],
        parties: usize,
        selected: Vec<usize>,
    ) -> Result<Self, String> {
        if !(2..=64).contains(&parties)
            || selected.len() < 3
            || selected.iter().any(|party| !(1..=parties).contains(party))
        {
            return Err("FROST process population or signing quorum is invalid".into());
        }
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let executable = executable.as_ref();
        let mut children = (0..parties)
            .map(|node| {
                ProofPartyChild::spawn(
                    executable,
                    u16::try_from(node).map_err(|_| "FROST node index overflows")?,
                    &root,
                )
            })
            .collect::<Result<Vec<_>, String>>()?;
        let public = distributed_setup(&mut children, session)?;
        Ok(Self {
            root,
            parties: children,
            public,
            selected,
        })
    }

    pub fn public(&self) -> &frost::keys::PublicKeyPackage {
        &self.public
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn sign_reserve_payment(
        &mut self,
        partial: &PartialInstruction,
        mandate: ReserveMandateRef<'_>,
    ) -> Result<frost::Signature, String> {
        let message = partial.digest();
        let signing_job = signing_job(&message);
        let mut params = mandate.public_params()?;
        let object = params
            .as_object_mut()
            .ok_or_else(|| "reserve mandate parameters are not an object".to_string())?;
        object.insert("signing_job_id".into(), json!(hex::encode(signing_job)));
        object.insert("message".into(), json!(BASE64.encode(message)));
        object.insert(
            "amount_commitment".into(),
            json!(hex::encode(partial.amount_commitment.compress().to_bytes())),
        );
        object.insert(
            "price_commitment".into(),
            json!(hex::encode(partial.price_commitment.compress().to_bytes())),
        );
        object.insert(
            "asset_commitment".into(),
            json!(hex::encode(partial.asset_commitment.compress().to_bytes())),
        );
        object.insert(
            "payer_handle".into(),
            json!(hex::encode(partial.payer_handle.compress().to_bytes())),
        );
        object.insert(
            "payee_handle".into(),
            json!(hex::encode(partial.payee_handle.compress().to_bytes())),
        );
        object.insert("deadline".into(), json!(partial.deadline));
        object.insert("nonce".into(), json!(hex::encode(partial.nonce)));
        match partial.quote_binding {
            QuoteBinding::LegacyPackedKey(value) => {
                object.insert("quote_kind".into(), json!("legacy"));
                object.insert("quote_key".into(), json!(value));
            }
            QuoteBinding::ProofDigest(value) => {
                object.insert("quote_kind".into(), json!("proof"));
                object.insert("quote_digest".into(), json!(hex::encode(value)));
            }
        }
        for party in &self.selected {
            self.parties[*party - 1].call("authorize_reserve_payment", params.clone())?;
        }
        let signature =
            distributed_sign(&mut self.parties, &self.selected, &message, &self.public)?;
        self.public
            .verifying_key()
            .verify(&message, &signature)
            .map_err(|_| "reserve payment threshold signature is invalid".to_string())?;
        Ok(signature)
    }

    pub fn sign_reserve_context(
        &mut self,
        payment: &qomm_zkpi::Instruction,
        context: &typed::ExecutionContext,
        mandate: ReserveMandateRef<'_>,
    ) -> Result<frost::Signature, String> {
        let message = typed::digest_for(payment, context, qomm_zkpi::DEFAULT_DOMAIN)
            .map_err(str::to_string)?;
        let signing_job = signing_job(&message);
        let mut params = mandate.public_params()?;
        let object = params
            .as_object_mut()
            .ok_or_else(|| "reserve mandate parameters are not an object".to_string())?;
        object.insert("signing_job_id".into(), json!(hex::encode(signing_job)));
        object.insert("message".into(), json!(BASE64.encode(message)));
        object.insert(
            "payment".into(),
            json!(BASE64.encode(payment_wire::encode(payment))),
        );
        object.insert(
            "context".into(),
            json!(BASE64.encode(typed_wire::encode_context(context))),
        );
        for party in &self.selected {
            self.parties[*party - 1].call("authorize_reserve_typed", params.clone())?;
        }
        let signature =
            distributed_sign(&mut self.parties, &self.selected, &message, &self.public)?;
        self.public
            .verifying_key()
            .verify(&message, &signature)
            .map_err(|_| "typed reserve threshold signature is invalid".to_string())?;
        Ok(signature)
    }

    pub fn close(mut self) -> Result<(), String> {
        for party in &mut self.parties {
            party.close()?;
        }
        Ok(())
    }
}

fn distributed_setup(
    parties: &mut [ProofPartyChild],
    session: [u8; 32],
) -> Result<frost::keys::PublicKeyPackage, String> {
    frost_coordinator::distributed_frost_setup(parties, session)
}

fn signing_job(message: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"QOMM:FROST:SIGNING-JOB:v1")
        .chain_update(message)
        .finalize()
        .into()
}

fn distributed_sign(
    parties: &mut [ProofPartyChild],
    selected: &[usize],
    message: &[u8],
    public: &frost::keys::PublicKeyPackage,
) -> Result<frost::Signature, String> {
    let job = signing_job(message);
    let encoded_message = BASE64.encode(message);
    let commitments = selected
        .iter()
        .map(|party| {
            parties[*party - 1].call(
                "frost_commit",
                json!({"job_id": hex::encode(job), "message": encoded_message}),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut decoded_commitments = BTreeMap::new();
    for commitment in &commitments {
        let party = commitment
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| "FROST commitment party is invalid".to_string())?;
        let raw = BASE64
            .decode(
                commitment
                    .get("commitments")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "FROST commitment is absent".to_string())?,
            )
            .map_err(|_| "FROST commitment is malformed")?;
        decoded_commitments.insert(
            frost::Identifier::try_from(party).map_err(|_| "FROST identifier is invalid")?,
            frost::round1::SigningCommitments::deserialize(&raw)
                .map_err(|_| "FROST commitment cannot be decoded")?,
        );
    }
    let commitment_values = Value::Array(commitments);
    let shares = selected
        .iter()
        .map(|party| {
            parties[*party - 1].call(
                "frost_sign",
                json!({
                    "job_id": hex::encode(job),
                    "message": encoded_message,
                    "commitments": commitment_values.clone(),
                }),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut decoded_shares = BTreeMap::new();
    for share in shares {
        let party = share
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| "FROST signature-share party is invalid".to_string())?;
        let raw = BASE64
            .decode(
                share
                    .get("share")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "FROST signature share is absent".to_string())?,
            )
            .map_err(|_| "FROST signature share is malformed")?;
        decoded_shares.insert(
            frost::Identifier::try_from(party).map_err(|_| "FROST identifier is invalid")?,
            frost::round2::SignatureShare::deserialize(&raw)
                .map_err(|_| "FROST signature share cannot be decoded")?,
        );
    }
    let package = frost::SigningPackage::new(decoded_commitments, message);
    frost::aggregate(&package, &decoded_shares, public)
        .map_err(|_| "FROST aggregation rejected a node response".into())
}
