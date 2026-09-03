//! Process-isolated threshold-proof participant.
//!
//! A coordinator may send public exponent evaluations, statements and Fiat-
//! Shamir challenges. It cannot request a scalar share or a first-round nonce:
//! neither has a request/response representation. Each process opens only its
//! own MP-SPDZ persistence file below a configured root.

use crate::mpc_result::NodePublicResultAttestation;
use crate::order::{
    admission_principal_digest, encode_node_execution_attestation, principal_ticket_id,
    NodeAdmissionAttestation, NodeExecutionAttestation,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use merlin::Transcript;
use qomm_audit::distributed_dp::DpMechanism;
use qomm_audit::publication::{NodePublicationEvidence, PublicationStatement};
use qomm_mpc::persistence::{
    read_local_dvp_handoff, read_local_dvp_handoff_from_quote, read_local_quote_proof_handoff,
    read_local_zkpi_handoff_from_dvp, read_local_zkpi_handoff_from_quote,
};
use qomm_proofs::opening_envelope::{encrypt_opening_share, opening_context};
use qomm_proofs::quote_proof::{
    quote_proof_digest, registered_policy_digest, Public as QuotePublic, QuoteCircuit,
    RegisteredPolicy,
};
use qomm_proofs::threshold_gadgets::coefficient_commitments_from_evaluations;
use qomm_proofs::threshold_quote::{
    assemble_quote_from_rounds, quote_relation_statements_from_evaluations,
    quote_statement_from_evaluations, QuoteNodeContribution, QuoteNodeStatement,
    QuoteRelationStatements, QuoteRound1Secrets,
};
use qomm_proofs::threshold_range::verify_threshold_range;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::verify_product;
use qomm_zkpi::{
    frost, typed, typed_wire, wire as payment_wire, Bounds, PartialInstruction, QuoteBinding,
    Venue, DEFAULT_DOMAIN,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::dvp_issuer::{
    statements_from_evaluations as dvp_statements, BoundMpcDvpNode, DvpRound1Secrets, MpcDvpNode,
    DVP_CASH_REMAINDER_CONTEXT, DVP_PRODUCT_CONTEXT, DVP_SECURITIES_REMAINDER_CONTEXT,
};
use crate::dvp_wire::{
    decode as decode_dvp, encode as encode_dvp, Envelope as DvpEnvelope, Message as DvpMessage,
};
use crate::key_management::{
    decrypt_authenticated, derive_secret_key, encrypt_authenticated, FileLock,
};
use crate::limit_issuer::{
    statement_from_evaluations as limit_statement, BoundMpcLimitNode, MpcLimitNode,
};
use crate::limit_wire::{
    decode as decode_limit, encode as encode_limit, Envelope as LimitEnvelope,
    Message as LimitMessage,
};
use crate::mandate::{MakerPolicyMandate, TakerExecutionMandate};
use crate::pretrade_authority::{decode_ack, ReservationParty};
use crate::proof_codec::decode_dvp_proofs;
use crate::proof_codec::decode_threshold_range;
use crate::quote_issuer::MpcQuoteNode;
use crate::quote_wire::{
    decode as decode_quote, encode as encode_quote, Envelope as QuoteEnvelope,
    Message as QuoteMessage,
};
use crate::selective_disclosure::{
    decrypt as decrypt_exchange, encrypt as encrypt_exchange, shared as exchange_shared,
    X25519PrivateKey, X25519PublicKey,
};
use crate::standing_pool::{
    standing_note_pool_delegation_digest, standing_note_pool_id, threshold_dvp_package_digest,
    threshold_dvp_sides, threshold_range_proof_digest, StandingPoolAllocationBinding,
    STANDING_POOL_REMAINDER_CONTEXT,
};
use crate::zkpi_issuer::{
    field_scalar, statements_from_evaluations as zkpi_statements, BoundMpcZkpiNode, MpcZkpiNode,
    ZkpiRound1Secrets, ZkpiStatements,
};
use crate::zkpi_wire::{
    decode as decode_zkpi, encode as encode_zkpi, Envelope as ZkpiEnvelope, Message as ZkpiMessage,
};

const MAX_JOBS: usize = 64;
const MAX_COMPLETED_EVIDENCE: usize = 4096;
const MAX_WIRES: usize = 64;
const MAX_WIRE_BYTES: usize = 1 << 20;
const MAX_REQUEST_BYTES: usize = 8 << 20;
const MAX_RESPONSE_BYTES: usize = 8 << 20;
const MAX_PROOF_STATE_BYTES: usize = 32 << 20;
const FROST_IDENTITY_DOMAIN: &[u8] = b"QOMM:FROST:PEER-IDENTITY:v1";
const FROST_MANIFEST_DOMAIN: &[u8] = b"QOMM:FROST:PEER-MANIFEST:v1";
const FROST_CONFIRM_DOMAIN: &[u8] = b"QOMM:FROST:PEER-CONFIRM:v1";
const FROST_EXCHANGE_DOMAIN: &[u8] = b"QOMM:FROST:DKG-EXCHANGE:v1";
const PROOF_STATE_MAGIC: &[u8; 8] = b"QOMMPS01";
const PROOF_STATE_AAD: &[u8] = b"QOMM:PROOF-PARTY-STATE:v1";
const PROOF_STATE_SALT_BYTES: usize = 16;
const PROOF_STATE_NONCE_BYTES: usize = 12;

enum ReserveMandate {
    Maker(MakerPolicyMandate),
    Taker(TakerExecutionMandate),
}

impl ReserveMandate {
    fn from_params(params: &Value) -> Result<Self, String> {
        let unsigned = ProofParty::one_wire(params, "mandate_unsigned")?;
        let signature: [u8; 64] = hex::decode(
            params
                .get("mandate_signature")
                .and_then(Value::as_str)
                .ok_or_else(|| "mandate_signature must be 64-byte hexadecimal".to_string())?,
        )
        .map_err(|_| "mandate_signature must be 64-byte hexadecimal".to_string())?
        .try_into()
        .map_err(|_| "mandate_signature must be 64-byte hexadecimal".to_string())?;
        match params.get("role").and_then(Value::as_str) {
            Some("maker") => Ok(Self::Maker(MakerPolicyMandate::from_signed_bytes(
                &unsigned, signature,
            )?)),
            Some("taker") => Ok(Self::Taker(TakerExecutionMandate::from_signed_bytes(
                &unsigned, signature,
            )?)),
            _ => Err("reserve signing role must be maker or taker".into()),
        }
    }

    fn verify_payment(
        &self,
        amount_commitment: &RistrettoPoint,
        payer_handle: &RistrettoPoint,
        deadline: u64,
        now: u64,
    ) -> Result<(), String> {
        match self {
            Self::Maker(mandate) => {
                mandate.verify_signature_at(now)?;
                if mandate.maximum_amount_commitment != amount_commitment.compress().to_bytes()
                    || mandate.maker_handle != payer_handle.compress().to_bytes()
                    || deadline > mandate.valid_until
                {
                    return Err("reserve payment differs from the signed Maker mandate".into());
                }
            }
            Self::Taker(mandate) => {
                mandate.verify_signature_at(now)?;
                if mandate.maximum_amount_commitment != amount_commitment.compress().to_bytes()
                    || mandate.taker_handle != payer_handle.compress().to_bytes()
                    || deadline > mandate.deadline
                {
                    return Err("reserve payment differs from the signed Taker mandate".into());
                }
            }
        }
        Ok(())
    }

    fn verify_context(
        &self,
        payment: &qomm_zkpi::Instruction,
        context: &typed::ExecutionContext,
        now: u64,
    ) -> Result<(), String> {
        self.verify_payment(
            &payment.amount_commitment,
            &payment.payer_handle,
            payment.deadline,
            now,
        )?;
        match self {
            Self::Maker(mandate) => {
                if context.scope != typed::AuthorizationScope::Maker
                    || context.direction as u8 != mandate.direction as u8
                    || context.venue_id != mandate.venue_id
                    || context.defmi_id != mandate.defmi_id
                    || context.maker_handle.compress().to_bytes() != mandate.maker_handle
                    || context.maker_reservation_id != mandate.reserve_id
                    || context.maker_policy_digest != mandate.policy_digest
                    || context.maker_mandate_digest != mandate.digest()?
                    || context.rfq_nullifier != [0; 32]
                {
                    return Err("typed reserve differs from the signed Maker mandate".into());
                }
            }
            Self::Taker(mandate) => {
                if context.scope != typed::AuthorizationScope::Taker
                    || context.direction as u8 != mandate.direction as u8
                    || context.venue_id != mandate.venue_id
                    || context.defmi_id != mandate.defmi_id
                    || context.taker_handle.compress().to_bytes() != mandate.taker_handle
                    || context.taker_reservation_id != mandate.reserve_id
                    || context.taker_mandate_digest != mandate.digest()?
                    || context.rfq_nullifier != mandate.rfq_nullifier
                {
                    return Err("typed reserve differs from the signed Taker mandate".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ProofPartyConfig {
    pub node: u16,
    pub allowed_root: PathBuf,
    /// Encrypted node-local state. Production deployments put this on the
    /// node's own durable volume; it must never be shared with the coordinator.
    pub state_file: PathBuf,
    /// Loaded from a node-local secret file or HSM-unwrapped secret by the
    /// process entry point. It is never represented in the JSON protocol.
    pub state_passphrase: Vec<u8>,
    pub n_mm: usize,
    /// Fixed proof/MPC committee population.  A proof node refuses a selected
    /// Maker-handle transcript that omits any configured participant.
    pub n_parties: usize,
    pub threshold: usize,
    pub amount_bits: usize,
    pub price_bits: usize,
    pub remainder_bits: usize,
    pub complete_quote_proof: bool,
    pub quote_eligibility_bits: usize,
    pub quote_span_bits: usize,
    /// Pinned DeFMI receipt key. Without it a node can prove a quote, but it
    /// cannot authorise a typed settlement against untrusted reservation IDs.
    pub trusted_defmi_receipt_public: Option<[u8; 32]>,
    /// Acceptance-only health signatures are domain-separated 32-byte probes.
    /// Production endpoints keep this false; zkPI signatures always require a
    /// successfully verified proof job.
    pub allow_health_signing: bool,
}

impl ProofPartyConfig {
    fn validate(&self) -> Result<(), String> {
        if self.node >= 64
            || self.n_mm == 0
            || self.n_mm > 4096
            || !(2..=64).contains(&self.n_parties)
            || self.node as usize >= self.n_parties
            || self.threshold == 0
            || self.threshold >= self.n_parties
            || !(1..=64).contains(&self.amount_bits)
            || !(1..=64).contains(&self.price_bits)
            || !(1..=64).contains(&self.remainder_bits)
            || !(1..=64).contains(&self.quote_eligibility_bits)
            || !(1..=64).contains(&self.quote_span_bits)
            || self.state_passphrase.len() < 16
        {
            return Err("proof-party configuration is outside its fixed bounds".into());
        }
        if self.complete_quote_proof && self.quote_eligibility_bits < 3 {
            return Err(
                "complete quote proofs need at least three eligibility witness bits".into(),
            );
        }
        if self
            .trusted_defmi_receipt_public
            .as_ref()
            .is_some_and(|key| VerifyingKey::from_bytes(key).is_err())
        {
            return Err("proof-party DeFMI receipt key is malformed".into());
        }
        Ok(())
    }

    fn security_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new()
            .chain_update(b"QOMM:PROOF-PARTY:SECURITY-CONFIG:v1")
            .chain_update(self.node.to_be_bytes())
            .chain_update((self.n_mm as u64).to_be_bytes())
            .chain_update((self.n_parties as u64).to_be_bytes())
            .chain_update((self.threshold as u64).to_be_bytes())
            .chain_update((self.amount_bits as u64).to_be_bytes())
            .chain_update((self.price_bits as u64).to_be_bytes())
            .chain_update((self.remainder_bits as u64).to_be_bytes())
            .chain_update([u8::from(self.complete_quote_proof)])
            .chain_update((self.quote_eligibility_bits as u64).to_be_bytes())
            .chain_update((self.quote_span_bits as u64).to_be_bytes())
            .chain_update([u8::from(self.allow_health_signing)]);
        match self.trusted_defmi_receipt_public {
            Some(public) => {
                digest = digest.chain_update([1]).chain_update(public);
            }
            None => {
                digest = digest.chain_update([0]);
            }
        }
        digest.finalize().into()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DurableProofState {
    version: u8,
    generation: u64,
    /// Binds every security-relevant proof setting to the encrypted key state.
    /// Reusing a FROST share after silently changing circuit widths or proof
    /// mode is rejected at startup.
    #[serde(default)]
    proof_configuration_digest: String,
    node: u16,
    n_mm: usize,
    #[serde(default = "default_proof_parties")]
    n_parties: usize,
    threshold: usize,
    #[serde(default)]
    trusted_defmi_receipt_public: Option<String>,
    identity_private: String,
    exchange_private: String,
    frost_session: Option<String>,
    frost_key_package: Option<String>,
    frost_public_package: Option<String>,
    /// Digest of the exact final DKG transcript accepted by this node.  It
    /// makes a lost finalization response safely retryable after a partial
    /// seven-node commit.
    #[serde(default)]
    frost_dkg_finalize_digest: Option<String>,
    /// Confirmed, signed DKG membership is persisted before round one.  This
    /// makes a coordinator/node restart in any pre-finalization phase
    /// resumable with the same session and participant set.
    #[serde(default)]
    frost_peer_manifest: Option<DurableFrostPeerManifest>,
    #[serde(default)]
    frost_dkg_round1: Option<DurableFrostDkgRound1>,
    /// Encrypted inside the proof-state envelope.  Persisting round two lets
    /// a node finish the exact journaled DKG transcript after a process or
    /// coordinator failure without exporting its temporary secret.
    #[serde(default)]
    frost_dkg_round2: Option<DurableFrostDkgRound2>,
    /// Reserved before a commitment leaves the node. A crash burns the job
    /// instead of allowing another signing attempt with a new nonce.
    frost_reserved: Vec<String>,
    frost_consumed: Vec<String>,
    #[serde(default)]
    frost_authorized: BTreeMap<String, String>,
    /// DP publication operation IDs signed from node-local MPC evidence.
    #[serde(default)]
    publication_consumed: Vec<String>,
    /// Reserved before proof evaluations leave the node. An interrupted proof
    /// must use a new identifier rather than replaying the same transcript.
    proof_reserved: Vec<String>,
    proof_completed: Vec<String>,
    #[serde(default)]
    completed_evidence: BTreeMap<String, DurableCompletedProof>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DurableFrostDkgRound2 {
    session: String,
    entries: Vec<FrostPeerEntry>,
    round1_package: String,
    secret_package: String,
    broadcasts_digest: String,
    encrypted: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DurableFrostPeerManifest {
    session: String,
    entries: Vec<FrostPeerEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DurableFrostDkgRound1 {
    secret_package: String,
    broadcast_package: String,
}

fn default_proof_parties() -> usize {
    7
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DurableCompletedProof {
    payment_digest: String,
    quote_digest: String,
    #[serde(default)]
    winning_policy_digest: Option<String>,
    typed_message_digest: Option<String>,
    /// Added after v1 deployment.  Old records remain readable, but are not
    /// eligible for typed settlement because they cannot prove which opaque
    /// account handles the MPC winner selected.
    #[serde(default)]
    maker_handle: Option<String>,
    #[serde(default)]
    taker_handle: Option<String>,
    #[serde(default)]
    maker_is_payer: Option<bool>,
    #[serde(default)]
    securities_reserve: Option<String>,
    #[serde(default)]
    cash_reserve: Option<String>,
}

#[derive(Clone)]
struct CompletedProof {
    payment_digest: [u8; 64],
    quote_digest: [u8; 32],
    winning_policy_digest: Option<[u8; 32]>,
    typed_message_digest: Option<[u8; 32]>,
    maker_handle: Option<[u8; 32]>,
    taker_handle: Option<[u8; 32]>,
    maker_is_payer: Option<bool>,
    securities_reserve: Option<[u8; 32]>,
    cash_reserve: Option<[u8; 32]>,
}

struct ProofStateStore {
    path: PathBuf,
    passphrase: Vec<u8>,
}

impl ProofStateStore {
    fn resolve(root: &Path, configured: &Path, passphrase: &[u8]) -> Result<Self, String> {
        let file_name = configured
            .file_name()
            .ok_or_else(|| "proof-party state path has no file name".to_string())?;
        let parent = if configured.is_absolute() {
            configured
                .parent()
                .ok_or_else(|| "proof-party state path has no parent".to_string())?
                .to_path_buf()
        } else {
            if configured.as_os_str().is_empty()
                || configured
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(
                    "proof-party state path must be a normalized file below its root".into(),
                );
            }
            root.join(configured)
                .parent()
                .ok_or_else(|| "proof-party state path has no parent".to_string())?
                .to_path_buf()
        };
        let parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
        let parent_metadata = parent.metadata().map_err(|error| error.to_string())?;
        // SAFETY: geteuid has no preconditions and reveals no secret.
        let effective_uid = unsafe { libc::geteuid() };
        if !parent.starts_with(root)
            || !parent_metadata.is_dir()
            || parent_metadata.permissions().mode() & 0o077 != 0
            || parent_metadata.uid() != effective_uid
        {
            return Err(
                "proof-party state parent must be a private directory below its node-local root"
                    .into(),
            );
        }
        let path = parent.join(file_name);
        if fs::symlink_metadata(&path)
            .ok()
            .is_some_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("proof-party state path must not be a symbolic link".into());
        }
        Ok(Self {
            path,
            passphrase: passphrase.to_vec(),
        })
    }

    fn read(&self) -> Result<DurableProofState, String> {
        let _lock = FileLock::acquire(&self.path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        // SAFETY: geteuid has no preconditions and reveals no secret.
        let effective_uid = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != effective_uid
        {
            return Err(
                "proof-party state must be an owner-only regular file owned by the service user"
                    .into(),
            );
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_PROOF_STATE_BYTES + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|error| error.to_string())?;
        if raw.len() > MAX_PROOF_STATE_BYTES {
            return Err("proof-party state exceeds its fixed bound".into());
        }
        let minimum =
            PROOF_STATE_MAGIC.len() + PROOF_STATE_SALT_BYTES + PROOF_STATE_NONCE_BYTES + 16;
        if raw.len() < minimum || raw.get(..PROOF_STATE_MAGIC.len()) != Some(PROOF_STATE_MAGIC) {
            return Err("not an encrypted QOMM proof-party state".into());
        }
        let mut at = PROOF_STATE_MAGIC.len();
        let salt = &raw[at..at + PROOF_STATE_SALT_BYTES];
        at += PROOF_STATE_SALT_BYTES;
        let nonce: &[u8; PROOF_STATE_NONCE_BYTES] = raw[at..at + PROOF_STATE_NONCE_BYTES]
            .try_into()
            .expect("fixed proof-state nonce");
        at += PROOF_STATE_NONCE_BYTES;
        let clear = decrypt_authenticated(
            &derive_secret_key(&self.passphrase, salt)?,
            nonce,
            PROOF_STATE_AAD,
            &raw[at..],
        )?;
        let state: DurableProofState = serde_json::from_slice(&clear)
            .map_err(|_| "proof-party state authentication failed".to_string())?;
        if state.version != 2 {
            return Err(
                "unsupported proof-party state version; securely reprovision this non-production node"
                    .into(),
            );
        }
        Ok(state)
    }

    fn write(&self, state: &DurableProofState) -> Result<(), String> {
        let _lock = FileLock::acquire(&self.path)?;
        let mut salt = [0_u8; PROOF_STATE_SALT_BYTES];
        let mut nonce = [0_u8; PROOF_STATE_NONCE_BYTES];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let clear = serde_json::to_vec(state).map_err(|error| error.to_string())?;
        let overhead =
            PROOF_STATE_MAGIC.len() + PROOF_STATE_SALT_BYTES + PROOF_STATE_NONCE_BYTES + 16;
        if clear.len().saturating_add(overhead) > MAX_PROOF_STATE_BYTES {
            return Err("proof-party state exceeds its fixed bound".into());
        }
        let ciphertext = encrypt_authenticated(
            &derive_secret_key(&self.passphrase, &salt)?,
            &nonce,
            PROOF_STATE_AAD,
            &clear,
        )?;
        let mut payload = Vec::with_capacity(
            PROOF_STATE_MAGIC.len()
                + PROOF_STATE_SALT_BYTES
                + PROOF_STATE_NONCE_BYTES
                + ciphertext.len(),
        );
        payload.extend_from_slice(PROOF_STATE_MAGIC);
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let temp = parent.join(format!(".qomm-proof-state-{}.tmp", rand::random::<u64>()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|error| error.to_string())?;
            file.write_all(&payload)
                .and_then(|_| file.sync_all())
                .map_err(|error| error.to_string())?;
            fs::rename(&temp, &self.path).map_err(|error| error.to_string())?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| error.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

struct ProofJob {
    expected_quote_digest: [u8; 32],
    persistence_digest: [u8; 32],
    authorized_payment_digest: Option<[u8; 64]>,
    authorized_taker_handle: Option<RistrettoPoint>,
    maker_is_payer: Option<bool>,
    maker_handle_share: Scalar,
    selected_maker_handle: Option<RistrettoPoint>,
    quote: Option<MpcQuoteNode>,
    quote_bound: Option<QuoteNodeContribution>,
    quote_statement: Option<QuoteNodeStatement>,
    quote_relations: Option<QuoteRelationStatements>,
    quote_public: Option<QuotePublic>,
    winning_policy_digest: Option<[u8; 32]>,
    quote_context: Option<Vec<u8>>,
    quote_round1: Option<QuoteRound1Secrets>,
    quote_verified: bool,
    zkpi: Option<MpcZkpiNode>,
    zkpi_bound: Option<BoundMpcZkpiNode>,
    zkpi_statements: Option<ZkpiStatements>,
    zkpi_round1: Option<ZkpiRound1Secrets>,
    limit: Option<MpcLimitNode>,
    limit_bound: Option<BoundMpcLimitNode>,
    limit_round1: Option<qomm_proofs::threshold_range::RangeRound1Secret>,
    pool_remainder: Option<MpcLimitNode>,
    pool_remainder_bound: Option<BoundMpcLimitNode>,
    pool_remainder_round1: Option<qomm_proofs::threshold_range::RangeRound1Secret>,
    pool_remainder_commitment: Option<RistrettoPoint>,
    pool_remainder_response_issued: bool,
    dvp: Option<MpcDvpNode>,
    dvp_bound: Option<BoundMpcDvpNode>,
    dvp_round1: Option<DvpRound1Secrets>,
    quantity_commitment: Option<RistrettoPoint>,
    cash_commitment: Option<RistrettoPoint>,
    securities_remainder: Option<RistrettoPoint>,
    cash_remainder: Option<RistrettoPoint>,
    securities_reserve: Option<RistrettoPoint>,
    cash_reserve: Option<RistrettoPoint>,
    /// Set only after this node has consumed its one-use DvP nonce and issued
    /// the public response. A standing-pool allocation cannot be authorized
    /// from evaluations alone.
    dvp_response_issued: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FrostPeerEntry {
    party: u16,
    identity_public: String,
    exchange_public: String,
    self_signature: String,
}

struct FrostPeer {
    identity: VerifyingKey,
    exchange: X25519PublicKey,
}

struct PendingPeers {
    session: [u8; 32],
    digest: [u8; 32],
    entries: Vec<FrostPeerEntry>,
    peers: BTreeMap<u16, FrostPeer>,
}

struct PendingDkgRound2 {
    secret: frost::keys::dkg::round2::SecretPackage,
    round1_package: Vec<u8>,
    broadcasts_digest: [u8; 32],
    encrypted: Vec<Value>,
}

struct PendingDkgRound1 {
    secret: frost::keys::dkg::round1::SecretPackage,
    broadcast_package: Vec<u8>,
}

struct FrostNonceState {
    message_digest: [u8; 32],
    nonces: frost::round1::SigningNonces,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofRequest {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofResponse {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct ProofParty {
    config: ProofPartyConfig,
    allowed_root: PathBuf,
    key: Pedersen,
    jobs: BTreeMap<[u8; 32], ProofJob>,
    reserved: BTreeSet<[u8; 32]>,
    completed: BTreeSet<[u8; 32]>,
    completed_evidence: BTreeMap<[u8; 32], CompletedProof>,
    identity: SigningKey,
    exchange: X25519PrivateKey,
    pending_peers: Option<PendingPeers>,
    peers: Option<PendingPeers>,
    dkg_round1: Option<PendingDkgRound1>,
    dkg_round2: Option<PendingDkgRound2>,
    frost_key: Option<frost::keys::KeyPackage>,
    frost_public: Option<frost::keys::PublicKeyPackage>,
    frost_session: Option<[u8; 32]>,
    frost_dkg_finalize_digest: Option<[u8; 32]>,
    frost_nonces: BTreeMap<[u8; 32], FrostNonceState>,
    frost_reserved: BTreeSet<[u8; 32]>,
    frost_consumed: BTreeSet<[u8; 32]>,
    /// signing job -> SHA-256(message), persisted before nonce generation.
    frost_authorized: BTreeMap<[u8; 32], [u8; 32]>,
    publication_consumed: BTreeSet<[u8; 32]>,
    state_store: ProofStateStore,
    state_generation: u64,
    state_healthy: bool,
}

impl ProofParty {
    pub fn new(config: ProofPartyConfig) -> Result<Self, String> {
        config.validate()?;
        let allowed_root = fs::canonicalize(&config.allowed_root)
            .map_err(|error| format!("proof-party root is unavailable: {error}"))?;
        if !allowed_root.is_dir() {
            return Err("proof-party root is not a directory".into());
        }
        let state_store =
            ProofStateStore::resolve(&allowed_root, &config.state_file, &config.state_passphrase)?;
        let state = if state_store.path.exists() {
            state_store.read()?
        } else {
            let identity = SigningKey::generate(&mut OsRng);
            let exchange = X25519PrivateKey::generate()?;
            let state = DurableProofState {
                version: 2,
                generation: 0,
                proof_configuration_digest: hex::encode(config.security_digest()),
                node: config.node,
                n_mm: config.n_mm,
                n_parties: config.n_parties,
                threshold: config.threshold,
                trusted_defmi_receipt_public: config.trusted_defmi_receipt_public.map(hex::encode),
                identity_private: BASE64.encode(identity.to_bytes()),
                exchange_private: BASE64.encode(exchange.raw_private_key()?),
                frost_session: None,
                frost_key_package: None,
                frost_public_package: None,
                frost_dkg_finalize_digest: None,
                frost_peer_manifest: None,
                frost_dkg_round1: None,
                frost_dkg_round2: None,
                frost_reserved: Vec::new(),
                frost_consumed: Vec::new(),
                frost_authorized: BTreeMap::new(),
                publication_consumed: Vec::new(),
                proof_reserved: Vec::new(),
                proof_completed: Vec::new(),
                completed_evidence: BTreeMap::new(),
            };
            state_store.write(&state)?;
            state
        };
        let stored_defmi_public = state
            .trusted_defmi_receipt_public
            .as_deref()
            .map(|value| {
                hex::decode(value)
                    .map_err(|_| "stored DeFMI receipt key is malformed".to_string())?
                    .try_into()
                    .map_err(|_| "stored DeFMI receipt key is malformed".to_string())
            })
            .transpose()?;
        let stored_configuration_digest: [u8; 32] = hex::decode(&state.proof_configuration_digest)
            .map_err(|_| "stored proof-party security configuration is malformed")?
            .try_into()
            .map_err(|_| "stored proof-party security configuration is malformed")?;
        if state.node != config.node
            || state.n_mm != config.n_mm
            || state.n_parties != config.n_parties
            || state.threshold != config.threshold
            || stored_defmi_public != config.trusted_defmi_receipt_public
            || stored_configuration_digest != config.security_digest()
        {
            return Err(
                "proof-party state belongs to another node or security configuration".into(),
            );
        }
        let decode32 = |encoded: &str, name: &str| -> Result<[u8; 32], String> {
            BASE64
                .decode(encoded)
                .map_err(|_| format!("{name} is malformed"))?
                .try_into()
                .map_err(|_| format!("{name} is malformed"))
        };
        let decode_set = |values: &[String], name: &str| -> Result<BTreeSet<[u8; 32]>, String> {
            values
                .iter()
                .map(|value| {
                    hex::decode(value)
                        .map_err(|_| format!("{name} contains a malformed identifier"))?
                        .try_into()
                        .map_err(|_| format!("{name} contains a malformed identifier"))
                })
                .collect()
        };
        let frost_session = state
            .frost_session
            .as_deref()
            .map(|value| {
                hex::decode(value)
                    .map_err(|_| "stored FROST session is malformed".to_string())?
                    .try_into()
                    .map_err(|_| "stored FROST session is malformed".to_string())
            })
            .transpose()?;
        let frost_dkg_finalize_digest = state
            .frost_dkg_finalize_digest
            .as_deref()
            .map(|value| {
                hex::decode(value)
                    .map_err(|_| "stored FROST finalization digest is malformed".to_string())?
                    .try_into()
                    .map_err(|_| "stored FROST finalization digest is malformed".to_string())
            })
            .transpose()?;
        let pending_manifest = state
            .frost_peer_manifest
            .as_ref()
            .map(
                |manifest| -> Result<([u8; 32], Vec<FrostPeerEntry>), String> {
                    let session = hex::decode(&manifest.session)
                        .map_err(|_| "stored FROST pending session is malformed".to_string())?
                        .try_into()
                        .map_err(|_| "stored FROST pending session is malformed".to_string())?;
                    if manifest.entries.len() != config.n_parties {
                        return Err("stored FROST peer manifest is incomplete".into());
                    }
                    Ok((session, manifest.entries.clone()))
                },
            )
            .transpose()?;
        let pending_round1 = state
            .frost_dkg_round1
            .as_ref()
            .map(|pending| -> Result<PendingDkgRound1, String> {
                let secret = frost::keys::dkg::round1::SecretPackage::deserialize(
                    &BASE64
                        .decode(&pending.secret_package)
                        .map_err(|_| "stored FROST round-one secret is malformed".to_string())?,
                )
                .map_err(|_| "stored FROST round-one secret is malformed".to_string())?;
                let broadcast_package = BASE64
                    .decode(&pending.broadcast_package)
                    .map_err(|_| "stored FROST round-one broadcast is malformed".to_string())?;
                if broadcast_package.is_empty() || broadcast_package.len() > MAX_WIRE_BYTES {
                    return Err("stored FROST round-one broadcast exceeds its bound".into());
                }
                frost::keys::dkg::round1::Package::deserialize(&broadcast_package)
                    .map_err(|_| "stored FROST round-one broadcast is malformed".to_string())?;
                Ok(PendingDkgRound1 {
                    secret,
                    broadcast_package,
                })
            })
            .transpose()?;
        let pending_round2 = state
            .frost_dkg_round2
            .as_ref()
            .map(|pending| -> Result<_, String> {
                let session: [u8; 32] = hex::decode(&pending.session)
                    .map_err(|_| "stored FROST pending session is malformed".to_string())?
                    .try_into()
                    .map_err(|_| "stored FROST pending session is malformed".to_string())?;
                let secret = frost::keys::dkg::round2::SecretPackage::deserialize(
                    &BASE64
                        .decode(&pending.secret_package)
                        .map_err(|_| "stored FROST round-two secret is malformed".to_string())?,
                )
                .map_err(|_| "stored FROST round-two secret is malformed".to_string())?;
                let round1_package = BASE64
                    .decode(&pending.round1_package)
                    .map_err(|_| "stored FROST round-one broadcast is malformed".to_string())?;
                if round1_package.is_empty() || round1_package.len() > MAX_WIRE_BYTES {
                    return Err("stored FROST round-one broadcast exceeds its bound".into());
                }
                frost::keys::dkg::round1::Package::deserialize(&round1_package)
                    .map_err(|_| "stored FROST round-one broadcast is malformed".to_string())?;
                let broadcasts_digest = hex::decode(&pending.broadcasts_digest)
                    .map_err(|_| "stored FROST broadcasts digest is malformed".to_string())?
                    .try_into()
                    .map_err(|_| "stored FROST broadcasts digest is malformed".to_string())?;
                if pending.encrypted.len() + 1 != config.n_parties {
                    return Err("stored FROST encrypted package set is incomplete".to_string());
                }
                Ok((
                    session,
                    pending.entries.clone(),
                    PendingDkgRound2 {
                        secret,
                        round1_package,
                        broadcasts_digest,
                        encrypted: pending.encrypted.clone(),
                    },
                ))
            })
            .transpose()?;
        if pending_round1.is_some() && pending_round2.is_some() {
            return Err("stored FROST state contains two DKG rounds at once".into());
        }
        if pending_round1.is_some() || pending_round2.is_some() {
            let manifest = pending_manifest
                .as_ref()
                .ok_or_else(|| "stored FROST DKG state has no peer manifest".to_string())?;
            if pending_round2
                .as_ref()
                .is_some_and(|(session, entries, _)| {
                    session != &manifest.0 || entries != &manifest.1
                })
            {
                return Err("stored FROST DKG state disagrees with its peer manifest".into());
            }
        }
        let frost_authorized = state
            .frost_authorized
            .iter()
            .map(|(job, message)| {
                Ok((
                    hex::decode(job)
                        .map_err(|_| "stored FROST authorization job is malformed")?
                        .try_into()
                        .map_err(|_| "stored FROST authorization job is malformed")?,
                    hex::decode(message)
                        .map_err(|_| "stored FROST authorization digest is malformed")?
                        .try_into()
                        .map_err(|_| "stored FROST authorization digest is malformed")?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let completed_evidence = state
            .completed_evidence
            .iter()
            .map(|(job, proof)| {
                let payment_digest: [u8; 64] = hex::decode(&proof.payment_digest)
                    .map_err(|_| "stored completed payment digest is malformed")?
                    .try_into()
                    .map_err(|_| "stored completed payment digest is malformed")?;
                let quote_digest: [u8; 32] = hex::decode(&proof.quote_digest)
                    .map_err(|_| "stored completed quote digest is malformed")?
                    .try_into()
                    .map_err(|_| "stored completed quote digest is malformed")?;
                let typed_message_digest = proof
                    .typed_message_digest
                    .as_deref()
                    .map(|value| {
                        hex::decode(value)
                            .map_err(|_| "stored typed message digest is malformed")?
                            .try_into()
                            .map_err(|_| "stored typed message digest is malformed")
                    })
                    .transpose()?;
                let winning_policy_digest = proof
                    .winning_policy_digest
                    .as_deref()
                    .map(|value| {
                        hex::decode(value)
                            .map_err(|_| "stored winning policy digest is malformed")?
                            .try_into()
                            .map_err(|_| "stored winning policy digest is malformed")
                    })
                    .transpose()?;
                let decode_optional_handle =
                    |value: &Option<String>, name: &str| -> Result<Option<[u8; 32]>, String> {
                        value
                            .as_deref()
                            .map(|encoded| {
                                let bytes: [u8; 32] = hex::decode(encoded)
                                    .map_err(|_| format!("stored {name} is malformed"))?
                                    .try_into()
                                    .map_err(|_| format!("stored {name} is malformed"))?;
                                CompressedRistretto(bytes)
                                    .decompress()
                                    .ok_or_else(|| format!("stored {name} is not canonical"))?;
                                Ok(bytes)
                            })
                            .transpose()
                    };
                Ok((
                    hex::decode(job)
                        .map_err(|_| "stored completed proof job is malformed")?
                        .try_into()
                        .map_err(|_| "stored completed proof job is malformed")?,
                    CompletedProof {
                        payment_digest,
                        quote_digest,
                        winning_policy_digest,
                        typed_message_digest,
                        maker_handle: decode_optional_handle(
                            &proof.maker_handle,
                            "completed Maker handle",
                        )?,
                        taker_handle: decode_optional_handle(
                            &proof.taker_handle,
                            "completed Taker handle",
                        )?,
                        maker_is_payer: proof.maker_is_payer,
                        securities_reserve: decode_optional_handle(
                            &proof.securities_reserve,
                            "completed securities reserve",
                        )?,
                        cash_reserve: decode_optional_handle(
                            &proof.cash_reserve,
                            "completed cash reserve",
                        )?,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let frost_key = state
            .frost_key_package
            .as_deref()
            .map(|value| {
                frost::keys::KeyPackage::deserialize(
                    &BASE64
                        .decode(value)
                        .map_err(|_| "stored FROST key package is malformed".to_string())?,
                )
                .map_err(|_| "stored FROST key package is malformed".to_string())
            })
            .transpose()?;
        let frost_public = state
            .frost_public_package
            .as_deref()
            .map(|value| {
                frost::keys::PublicKeyPackage::deserialize(
                    &BASE64
                        .decode(value)
                        .map_err(|_| "stored FROST public package is malformed".to_string())?,
                )
                .map_err(|_| "stored FROST public package is malformed".to_string())
            })
            .transpose()?;
        if frost_key.is_some() != frost_public.is_some()
            || frost_key.is_some() != frost_session.is_some()
            || (frost_dkg_finalize_digest.is_some() && frost_key.is_none())
        {
            return Err("stored FROST state is incomplete".into());
        }
        let mut party = Self {
            config,
            allowed_root,
            key: Pedersen::new(b"qomm:defmi:v1"),
            jobs: BTreeMap::new(),
            reserved: decode_set(&state.proof_reserved, "stored proof reservations")?,
            completed: decode_set(&state.proof_completed, "stored completed proofs")?,
            completed_evidence,
            identity: SigningKey::from_bytes(&decode32(
                &state.identity_private,
                "stored FROST identity",
            )?),
            exchange: X25519PrivateKey::from_raw(&decode32(
                &state.exchange_private,
                "stored FROST exchange key",
            )?)?,
            pending_peers: None,
            peers: None,
            dkg_round1: pending_round1,
            dkg_round2: pending_round2.map(|(_, _, pending)| pending),
            frost_key,
            frost_public,
            frost_session,
            frost_dkg_finalize_digest,
            frost_nonces: BTreeMap::new(),
            frost_reserved: decode_set(&state.frost_reserved, "stored FROST reservations")?,
            frost_consumed: decode_set(&state.frost_consumed, "stored FROST completions")?,
            frost_authorized,
            publication_consumed: decode_set(
                &state.publication_consumed,
                "stored publication completions",
            )?,
            state_store,
            state_generation: state.generation,
            state_healthy: true,
        };
        if let Some((session, entries)) = pending_manifest {
            if party.frost_key.is_some() {
                return Err("stored FROST state is both pending and finalized".into());
            }
            party.peers = Some(party.manifest(session, entries)?);
        } else if party.dkg_round1.is_some() || party.dkg_round2.is_some() {
            return Err("stored FROST DKG state has no authenticated peers".into());
        }
        if !party.reserved.is_disjoint(&party.completed)
            || !party.frost_reserved.is_disjoint(&party.frost_consumed)
            || party.completed_evidence.len() > MAX_COMPLETED_EVIDENCE
            || party
                .completed_evidence
                .keys()
                .any(|job| !party.completed.contains(job))
            || party
                .frost_authorized
                .keys()
                .any(|job| party.frost_reserved.contains(job) || party.frost_consumed.contains(job))
        {
            return Err("proof-party state contains contradictory lifecycle sets".into());
        }
        Ok(party)
    }

    /// Stable public identity used by deployment acceptance.  Replacing the
    /// node-local proof state changes this value, while an ordinary process
    /// restart preserves it.
    pub fn instance_id(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"QOMM:PROOF-PARTY:INSTANCE:v2")
            .chain_update(self.config.security_digest())
            .chain_update(self.identity.verifying_key().to_bytes())
            .finalize()
            .into()
    }

    /// Sign the exact legal-entity claim and node-local share batch admitted at
    /// the MP-SPDZ execution boundary.  The principal is authenticated by the
    /// node's transport in production; the public Docker network passes its
    /// pinned participant identifier explicitly because it has no TLS proxy.
    ///
    /// The Taker signs `claim_digest` before submitting the RFQ.  Every node
    /// recomputes the slot-bound ticket and principal digest, and binds its own
    /// distinct input batch.  The coordinator therefore cannot replace the
    /// Taker mandate or manufacture an order after observing the quote.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_admission_attestation(
        &self,
        slot: u64,
        sequence: u64,
        principal: &str,
        ticket_id: [u8; 32],
        claim_digest: [u8; 32],
        batch_digest: [u8; 32],
        order_digest: [u8; 32],
    ) -> Result<(NodeAdmissionAttestation, [u8; 32]), String> {
        if !self.state_healthy {
            return Err("proof-party durable state is unavailable; node is fail-closed".into());
        }
        let slot_u32 = u32::try_from(slot)
            .map_err(|_| "admission slot is outside the resident-node range".to_string())?;
        if principal_ticket_id(slot_u32, principal)? != ticket_id {
            return Err(
                "admission ticket does not match the authenticated principal and slot".into(),
            );
        }
        let attestation = NodeAdmissionAttestation {
            node: self.config.node,
            slot,
            sequence,
            principal_digest: admission_principal_digest(principal)?,
            ticket_id,
            claim_digest,
            batch_digest,
            order_digest,
            signature: Signature::from_bytes(&[0_u8; 64]),
        }
        .sign(&self.identity)?;
        Ok((attestation, self.identity.verifying_key().to_bytes()))
    }

    /// Sign the Taker-masked public result emitted by this node's completed
    /// MP-SPDZ process. The caller supplies only public digests and outputs;
    /// no persistence share or unmasked quote crosses this boundary.
    pub fn sign_public_result_attestation(
        &self,
        attestation: NodePublicResultAttestation,
    ) -> Result<(NodePublicResultAttestation, [u8; 32]), String> {
        if !self.state_healthy {
            return Err("proof-party durable state is unavailable; node is fail-closed".into());
        }
        if attestation.node != self.config.node {
            return Err("public MPC result was routed to another resident node".into());
        }
        let signed = attestation.sign(&self.identity)?;
        Ok((signed, self.identity.verifying_key().to_bytes()))
    }

    fn durable_state(&self, generation: u64) -> Result<DurableProofState, String> {
        let encode_set =
            |values: &BTreeSet<[u8; 32]>| values.iter().map(hex::encode).collect::<Vec<_>>();
        Ok(DurableProofState {
            version: 2,
            generation,
            proof_configuration_digest: hex::encode(self.config.security_digest()),
            node: self.config.node,
            n_mm: self.config.n_mm,
            n_parties: self.config.n_parties,
            threshold: self.config.threshold,
            trusted_defmi_receipt_public: self.config.trusted_defmi_receipt_public.map(hex::encode),
            identity_private: BASE64.encode(self.identity.to_bytes()),
            exchange_private: BASE64.encode(self.exchange.raw_private_key()?),
            frost_session: self.frost_session.map(hex::encode),
            frost_key_package: self
                .frost_key
                .as_ref()
                .map(|key| {
                    key.serialize()
                        .map(|raw| BASE64.encode(raw))
                        .map_err(|_| "FROST key package serialization failed".to_string())
                })
                .transpose()?,
            frost_public_package: self
                .frost_public
                .as_ref()
                .map(|key| {
                    key.serialize()
                        .map(|raw| BASE64.encode(raw))
                        .map_err(|_| "FROST public package serialization failed".to_string())
                })
                .transpose()?,
            frost_dkg_finalize_digest: self.frost_dkg_finalize_digest.map(hex::encode),
            frost_peer_manifest: self.peers.as_ref().map(|peers| DurableFrostPeerManifest {
                session: hex::encode(peers.session),
                entries: peers.entries.clone(),
            }),
            frost_dkg_round1: self
                .dkg_round1
                .as_ref()
                .map(|pending| -> Result<DurableFrostDkgRound1, String> {
                    Ok(DurableFrostDkgRound1 {
                        secret_package: BASE64.encode(pending.secret.serialize().map_err(
                            |_| "FROST round-one secret serialization failed".to_string(),
                        )?),
                        broadcast_package: BASE64.encode(&pending.broadcast_package),
                    })
                })
                .transpose()?,
            frost_dkg_round2: self
                .dkg_round2
                .as_ref()
                .map(|pending| -> Result<DurableFrostDkgRound2, String> {
                    let peers = self.peers.as_ref().ok_or_else(|| {
                        "FROST round-two state has no authenticated peer manifest".to_string()
                    })?;
                    Ok(DurableFrostDkgRound2 {
                        session: hex::encode(peers.session),
                        entries: peers.entries.clone(),
                        round1_package: BASE64.encode(&pending.round1_package),
                        secret_package: BASE64.encode(pending.secret.serialize().map_err(
                            |_| "FROST round-two secret serialization failed".to_string(),
                        )?),
                        broadcasts_digest: hex::encode(pending.broadcasts_digest),
                        encrypted: pending.encrypted.clone(),
                    })
                })
                .transpose()?,
            frost_reserved: encode_set(&self.frost_reserved),
            frost_consumed: encode_set(&self.frost_consumed),
            frost_authorized: self
                .frost_authorized
                .iter()
                .map(|(job, message)| (hex::encode(job), hex::encode(message)))
                .collect(),
            publication_consumed: encode_set(&self.publication_consumed),
            proof_reserved: encode_set(&self.reserved),
            proof_completed: encode_set(&self.completed),
            completed_evidence: self
                .completed_evidence
                .iter()
                .map(|(job, proof)| {
                    (
                        hex::encode(job),
                        DurableCompletedProof {
                            payment_digest: hex::encode(proof.payment_digest),
                            quote_digest: hex::encode(proof.quote_digest),
                            winning_policy_digest: proof.winning_policy_digest.map(hex::encode),
                            typed_message_digest: proof.typed_message_digest.map(hex::encode),
                            maker_handle: proof.maker_handle.map(hex::encode),
                            taker_handle: proof.taker_handle.map(hex::encode),
                            maker_is_payer: proof.maker_is_payer,
                            securities_reserve: proof.securities_reserve.map(hex::encode),
                            cash_reserve: proof.cash_reserve.map(hex::encode),
                        },
                    )
                })
                .collect(),
        })
    }

    fn persist(&mut self) -> Result<(), String> {
        let generation = self
            .state_generation
            .checked_add(1)
            .ok_or_else(|| "proof-party state generation overflow".to_string())?;
        let state = self.durable_state(generation)?;
        if let Err(error) = self.state_store.write(&state) {
            self.state_healthy = false;
            return Err(format!(
                "proof-party durable state failed; node is fail-closed: {error}"
            ));
        }
        self.state_generation = generation;
        Ok(())
    }

    fn job_id(params: &Value) -> Result<[u8; 32], String> {
        let encoded = params
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "job_id must be a 32-byte hexadecimal digest".to_string())?;
        hex::decode(encoded)
            .map_err(|_| "job_id must be a 32-byte hexadecimal digest".to_string())?
            .try_into()
            .map_err(|_| "job_id must be a 32-byte hexadecimal digest".to_string())
    }

    fn job_mut(&mut self, id: &[u8; 32]) -> Result<&mut ProofJob, String> {
        self.jobs
            .get_mut(id)
            .ok_or_else(|| "proof job is not loaded on this node".to_string())
    }

    fn safe_persistence(&self, relative: &str) -> Result<PathBuf, String> {
        let relative = Path::new(relative);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return Err("persistence path must be a safe relative path".into());
        }
        let path = fs::canonicalize(self.allowed_root.join(relative))
            .map_err(|error| format!("node-local persistence is unavailable: {error}"))?;
        if !path.starts_with(&self.allowed_root)
            || path.file_name().and_then(|name| name.to_str())
                != Some(&format!("Transactions-P{}.data", self.config.node))
        {
            return Err("proof party may open only its own MP-SPDZ persistence file".into());
        }
        let metadata = path.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("node-local persistence must be a non-empty private file".into());
        }
        Ok(path)
    }

    fn publication_evidence(&self, relative: &str) -> Result<NodePublicationEvidence, String> {
        let relative = Path::new(relative);
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return Err("publication evidence path must be a safe relative path".into());
        }
        let path = fs::canonicalize(self.allowed_root.join(relative))
            .map_err(|error| format!("node-local publication evidence is unavailable: {error}"))?;
        if !path.starts_with(&self.allowed_root)
            || path.file_name().and_then(|name| name.to_str())
                != Some(&format!("dp-publication-P{}.json", self.config.node))
        {
            return Err("proof party may open only its own DP publication evidence".into());
        }
        let metadata = path.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > 64 * 1024
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("node-local publication evidence must be a bounded private file".into());
        }
        let raw = fs::read(&path).map_err(|error| error.to_string())?;
        serde_json::from_slice(&raw)
            .map_err(|_| "node-local publication evidence is malformed".into())
    }

    fn decode_wires(params: &Value, name: &str) -> Result<Vec<Vec<u8>>, String> {
        let wires = params
            .get(name)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{name} must be a bounded public-wire array"))?;
        if wires.is_empty() || wires.len() > MAX_WIRES {
            return Err(format!("{name} is outside the public-wire bound"));
        }
        wires
            .iter()
            .map(|wire| {
                let raw = BASE64
                    .decode(
                        wire.as_str()
                            .ok_or_else(|| format!("{name} contains a non-string wire"))?,
                    )
                    .map_err(|_| format!("{name} contains invalid base64"))?;
                if raw.is_empty() || raw.len() > MAX_WIRE_BYTES {
                    return Err(format!("{name} contains an oversized wire"));
                }
                Ok(raw)
            })
            .collect()
    }

    fn one_wire(params: &Value, name: &str) -> Result<Vec<u8>, String> {
        let raw = BASE64
            .decode(
                params
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{name} must be a public-wire string"))?,
            )
            .map_err(|_| format!("{name} contains invalid base64"))?;
        if raw.is_empty() || raw.len() > MAX_WIRE_BYTES {
            return Err(format!("{name} is outside the public-wire bound"));
        }
        Ok(raw)
    }

    fn encoded_zkpi(job_id: [u8; 32], message: ZkpiMessage) -> Result<Value, String> {
        Ok(Value::String(BASE64.encode(
            encode_zkpi(&ZkpiEnvelope { job_id, message }).map_err(|error| error.to_string())?,
        )))
    }

    fn encoded_dvp(job_id: [u8; 32], message: DvpMessage) -> Result<Value, String> {
        Ok(Value::String(BASE64.encode(
            encode_dvp(&DvpEnvelope { job_id, message }).map_err(|error| error.to_string())?,
        )))
    }

    fn encoded_limit(job_id: [u8; 32], message: LimitMessage) -> Result<Value, String> {
        Ok(Value::String(
            BASE64.encode(encode_limit(&LimitEnvelope { job_id, message })?),
        ))
    }

    fn encoded_quote(job_id: [u8; 32], message: QuoteMessage) -> Result<Value, String> {
        Ok(Value::String(
            BASE64.encode(encode_quote(&QuoteEnvelope { job_id, message })?),
        ))
    }

    fn hex32(value: Option<&Value>, name: &str) -> Result<[u8; 32], String> {
        hex::decode(
            value
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{name} must be a 32-byte hexadecimal value"))?,
        )
        .map_err(|_| format!("{name} must be a 32-byte hexadecimal value"))?
        .try_into()
        .map_err(|_| format!("{name} must be a 32-byte hexadecimal value"))
    }

    fn point(value: Option<&Value>, name: &str) -> Result<RistrettoPoint, String> {
        CompressedRistretto(Self::hex32(value, name)?)
            .decompress()
            .ok_or_else(|| format!("{name} must be a canonical Ristretto point"))
    }

    fn quote_public(params: &Value) -> Result<(QuotePublic, usize, u64, Vec<u8>), String> {
        let body = params
            .get("public")
            .and_then(Value::as_object)
            .ok_or_else(|| "quote public statement must be an object".to_string())?;
        let signed = |name: &str| -> Result<i64, String> {
            body.get(name)
                .and_then(Value::as_i64)
                .ok_or_else(|| format!("quote {name} must be a signed 64-bit integer"))
        };
        let unsigned = |name: &str| -> Result<u64, String> {
            body.get(name)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("quote {name} must be an unsigned 64-bit integer"))
        };
        let registry = body
            .get("registry")
            .and_then(Value::as_array)
            .filter(|entries| !entries.is_empty() && entries.len() <= 4096)
            .ok_or_else(|| "quote registry is empty or exceeds 4096 Makers".to_string())?
            .iter()
            .map(|entry| {
                let entry = entry
                    .as_object()
                    .ok_or_else(|| "quote registry entry must be an object".to_string())?;
                let maker_asset = entry
                    .get("maker_asset")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| "quote Maker asset is outside u32".to_string())?;
                Ok(RegisteredPolicy {
                    maker_asset,
                    ask_level: Self::point(entry.get("ask_level"), "registered ask level")?,
                    spread: Self::point(entry.get("spread"), "registered spread")?,
                    slope: Self::point(entry.get("slope"), "registered slope")?,
                    invcoef: Self::point(entry.get("invcoef"), "registered inventory coefficient")?,
                    inv: Self::point(entry.get("inv"), "registered inventory")?,
                    maxqty: Self::point(entry.get("maxqty"), "registered maximum quantity")?,
                    expiry: Self::point(entry.get("expiry"), "registered expiry")?,
                    active: Self::point(entry.get("active"), "registered active flag")?,
                    use_ref: Self::point(entry.get("use_ref"), "registered reference flag")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let direction = unsigned("direction").and_then(|value| {
            u8::try_from(value).map_err(|_| "quote direction exceeds u8".into())
        })?;
        let asset = unsigned("asset")
            .and_then(|value| u32::try_from(value).map_err(|_| "quote asset exceeds u32".into()))?;
        let public = QuotePublic {
            qty_commitment: Self::point(body.get("qty_commitment"), "quote quantity commitment")?,
            now: signed("now")?,
            sentinel: signed("sentinel")?,
            n_slots: signed("n_slots")?,
            direction,
            asset,
            reference_price: signed("reference_price")?,
            registry_digest: Self::hex32(body.get("registry_digest"), "quote registry digest")?,
            registry,
            market_digest: Self::hex32(body.get("market_digest"), "quote market digest")?,
            slot: unsigned("slot")?,
        };
        let winner_index = unsigned("winner_index").and_then(|value| {
            usize::try_from(value).map_err(|_| "winner index is invalid".into())
        })?;
        let winner_value = unsigned("winner_value")?;
        let context = Self::one_wire(params, "quote_context")?;
        if context.len() > 4096 {
            return Err("quote context exceeds 4096 bytes".into());
        }
        Ok((public, winner_index, winner_value, context))
    }

    fn signing_job(message: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"QOMM:FROST:SIGNING-JOB:v1")
            .chain_update(message)
            .finalize()
            .into()
    }

    fn authorize_frost(&mut self, signing_job: [u8; 32], message: &[u8]) -> Result<(), String> {
        if signing_job != Self::signing_job(message)
            || self.frost_reserved.contains(&signing_job)
            || self.frost_consumed.contains(&signing_job)
            || self.frost_nonces.contains_key(&signing_job)
        {
            return Err("FROST authorization names an invalid or used signing job".into());
        }
        let digest: [u8; 32] = Sha256::digest(message).into();
        if self
            .frost_authorized
            .insert(signing_job, digest)
            .is_some_and(|prior| prior != digest)
        {
            return Err("FROST signing authorization was changed".into());
        }
        self.persist()
    }

    fn identity_body(
        session: &[u8; 32],
        party: u16,
        identity: &[u8; 32],
        exchange: &[u8; 32],
    ) -> Vec<u8> {
        [
            FROST_IDENTITY_DOMAIN,
            session,
            &party.to_be_bytes(),
            identity,
            exchange,
        ]
        .concat()
    }

    fn active_frost_session(&self) -> Option<[u8; 32]> {
        self.frost_session
            .or_else(|| self.peers.as_ref().map(|peers| peers.session))
            .or_else(|| self.pending_peers.as_ref().map(|peers| peers.session))
    }

    fn peer_confirmation(&self, peers: &PendingPeers) -> Value {
        let confirmation = self
            .identity
            .sign(&[FROST_CONFIRM_DOMAIN, &peers.session, &peers.digest].concat());
        json!({
            "party": self.config.node + 1,
            "manifest_digest": hex::encode(peers.digest),
            "confirmation": hex::encode(confirmation.to_bytes()),
        })
    }

    fn verify_peer_confirmations(peers: &PendingPeers, params: &Value) -> Result<(), String> {
        let confirmations = params
            .get("confirmations")
            .and_then(Value::as_array)
            .ok_or_else(|| "FROST peer confirmations must be an array".to_string())?;
        if confirmations.len() != peers.entries.len() {
            return Err("FROST peer confirmation set is incomplete".into());
        }
        let body = [FROST_CONFIRM_DOMAIN, &peers.session, &peers.digest].concat();
        let mut seen = BTreeSet::new();
        for confirmation in confirmations {
            let party = confirmation
                .get("party")
                .and_then(Value::as_u64)
                .and_then(|party| u16::try_from(party).ok())
                .ok_or_else(|| "FROST confirmation party is invalid".to_string())?;
            if !seen.insert(party) {
                return Err("FROST confirmation party is duplicated".into());
            }
            let raw: [u8; 64] = hex::decode(
                confirmation
                    .get("confirmation")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "FROST peer confirmation is absent".to_string())?,
            )
            .map_err(|_| "FROST peer confirmation is malformed")?
            .try_into()
            .map_err(|_| "FROST peer confirmation is malformed")?;
            peers
                .peers
                .get(&party)
                .ok_or_else(|| "FROST confirmation names an unknown peer".to_string())?
                .identity
                .verify(&body, &Signature::from_bytes(&raw))
                .map_err(|_| "FROST manifest lacks an authentic peer confirmation")?;
        }
        Ok(())
    }

    fn manifest(
        &self,
        session: [u8; 32],
        mut entries: Vec<FrostPeerEntry>,
    ) -> Result<PendingPeers, String> {
        entries.sort_by_key(|entry| entry.party);
        if entries.len() < self.config.threshold + 1 || entries.len() > 64 {
            return Err("FROST peer manifest is outside its participant bound".into());
        }
        let mut peers = BTreeMap::new();
        let mut body = Vec::new();
        body.extend_from_slice(FROST_MANIFEST_DOMAIN);
        body.extend_from_slice(&session);
        body.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for (index, entry) in entries.iter().enumerate() {
            if entry.party as usize != index + 1 {
                return Err("FROST peer manifest parties must be contiguous and one-based".into());
            }
            let identity_raw: [u8; 32] = hex::decode(&entry.identity_public)
                .map_err(|_| "FROST identity key is malformed")?
                .try_into()
                .map_err(|_| "FROST identity key is malformed")?;
            let exchange_raw: [u8; 32] = hex::decode(&entry.exchange_public)
                .map_err(|_| "FROST exchange key is malformed")?
                .try_into()
                .map_err(|_| "FROST exchange key is malformed")?;
            let signature_raw: [u8; 64] = hex::decode(&entry.self_signature)
                .map_err(|_| "FROST peer self-signature is malformed")?
                .try_into()
                .map_err(|_| "FROST peer self-signature is malformed")?;
            let identity = VerifyingKey::from_bytes(&identity_raw)
                .map_err(|_| "FROST identity key is not canonical")?;
            identity
                .verify(
                    &Self::identity_body(&session, entry.party, &identity_raw, &exchange_raw),
                    &Signature::from_bytes(&signature_raw),
                )
                .map_err(|_| "FROST exchange key lacks its node identity signature")?;
            body.extend_from_slice(&entry.party.to_be_bytes());
            body.extend_from_slice(&identity_raw);
            body.extend_from_slice(&exchange_raw);
            body.extend_from_slice(&signature_raw);
            peers.insert(
                entry.party,
                FrostPeer {
                    identity,
                    exchange: X25519PublicKey::from_raw(&exchange_raw)?,
                },
            );
        }
        let own_party = self.config.node + 1;
        let own = entries
            .get(self.config.node as usize)
            .ok_or_else(|| "FROST manifest omits this node".to_string())?;
        if own.party != own_party
            || own.identity_public != hex::encode(self.identity.verifying_key().to_bytes())
            || own.exchange_public != hex::encode(self.exchange.public_key()?.raw_public_key()?)
        {
            return Err("FROST manifest substituted this node's identity or exchange key".into());
        }
        Ok(PendingPeers {
            session,
            digest: Sha256::digest(body).into(),
            entries,
            peers,
        })
    }

    fn exchange_aad(session: &[u8; 32], sender: u16, recipient: u16) -> Vec<u8> {
        [
            FROST_EXCHANGE_DOMAIN,
            session,
            &sender.to_be_bytes(),
            &recipient.to_be_bytes(),
        ]
        .concat()
    }

    fn exchange_key(
        &self,
        session: &[u8; 32],
        sender: u16,
        recipient: u16,
        peer: &X25519PublicKey,
    ) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(FROST_EXCHANGE_DOMAIN)
            .chain_update(session)
            .chain_update(sender.to_be_bytes())
            .chain_update(recipient.to_be_bytes())
            .chain_update(exchange_shared(&self.exchange, peer)?)
            .finalize()
            .into())
    }

    fn frost_broadcasts(
        &self,
        params: &Value,
        peers: &PendingPeers,
    ) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>, String> {
        let values = params
            .get("broadcasts")
            .and_then(Value::as_array)
            .ok_or_else(|| "FROST DKG broadcasts must be an array".to_string())?;
        if values.len() != peers.entries.len() {
            return Err("FROST DKG broadcast set is incomplete".into());
        }
        let mut result = BTreeMap::new();
        for value in values {
            let party = value
                .get("party")
                .and_then(Value::as_u64)
                .and_then(|party| u16::try_from(party).ok())
                .ok_or_else(|| "FROST DKG broadcast party is invalid".to_string())?;
            if !peers.peers.contains_key(&party) {
                return Err("FROST DKG broadcast names an unknown party".into());
            }
            let raw = BASE64
                .decode(
                    value
                        .get("package")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "FROST DKG broadcast package is absent".to_string())?,
                )
                .map_err(|_| "FROST DKG broadcast is not base64")?;
            if raw.is_empty() || raw.len() > MAX_WIRE_BYTES {
                return Err("FROST DKG broadcast exceeds its bound".into());
            }
            let identifier = frost::Identifier::try_from(party)
                .map_err(|_| "FROST DKG identifier is invalid")?;
            if result
                .insert(
                    identifier,
                    frost::keys::dkg::round1::Package::deserialize(&raw)
                        .map_err(|_| "FROST DKG broadcast cannot be decoded")?,
                )
                .is_some()
            {
                return Err("FROST DKG broadcast party is duplicated".into());
            }
        }
        Ok(result)
    }

    pub fn handle(&mut self, request: ProofRequest) -> ProofResponse {
        let result = self.dispatch(&request.method, &request.params);
        match result {
            Ok(result) => ProofResponse {
                id: request.id,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => ProofResponse {
                id: request.id,
                ok: false,
                result: None,
                error: Some(error.chars().take(512).collect()),
            },
        }
    }

    fn dispatch(&mut self, method: &str, params: &Value) -> Result<Value, String> {
        if !self.state_healthy {
            return Err("proof-party durable state is unavailable; node is fail-closed".into());
        }
        match method {
            "frost_status" => {
                let public_package = self
                    .frost_public
                    .as_ref()
                    .map(|public| {
                        public
                            .serialize()
                            .map(|raw| BASE64.encode(raw))
                            .map_err(|_| "FROST public package serialization failed".to_string())
                    })
                    .transpose()?;
                Ok(json!({
                    "party": self.config.node + 1,
                    "ready": public_package.is_some(),
                    "session": self.active_frost_session().map(hex::encode),
                    "stage": if self.frost_key.is_some() {
                        "ready"
                    } else if self.dkg_round2.is_some() {
                        "round2"
                    } else if self.dkg_round1.is_some() {
                        "round1"
                    } else if self.peers.is_some() {
                        "peers-confirmed"
                    } else if self.pending_peers.is_some() {
                        "peers-proposed"
                    } else {
                        "fresh"
                    },
                    "public_package": public_package,
                    "state_generation": self.state_generation,
                }))
            }
            "frost_identity" => {
                let session = Self::hex32(params.get("session"), "FROST session")?;
                if self
                    .active_frost_session()
                    .is_some_and(|active| active != session)
                {
                    return Err("FROST node is already bound to another DKG session".into());
                }
                let party = self.config.node + 1;
                let identity_public = self.identity.verifying_key().to_bytes();
                let exchange_public = self.exchange.public_key()?.raw_public_key()?;
                let signature = self.identity.sign(&Self::identity_body(
                    &session,
                    party,
                    &identity_public,
                    &exchange_public,
                ));
                Ok(json!({
                    "party": party,
                    "identity_public": hex::encode(identity_public),
                    "exchange_public": hex::encode(exchange_public),
                    "self_signature": hex::encode(signature.to_bytes()),
                }))
            }
            "frost_configure_peers" => {
                let session = Self::hex32(params.get("session"), "FROST session")?;
                let entries: Vec<FrostPeerEntry> = serde_json::from_value(
                    params
                        .get("entries")
                        .cloned()
                        .ok_or_else(|| "FROST peer entries are absent".to_string())?,
                )
                .map_err(|_| "FROST peer entries are malformed")?;
                let pending = self.manifest(session, entries)?;
                if self.frost_key.is_some() {
                    return Err("FROST group is already finalized on this node".into());
                }
                if let Some(existing) = self.peers.as_ref().or(self.pending_peers.as_ref()) {
                    if existing.session != pending.session || existing.digest != pending.digest {
                        return Err("FROST peer manifest was already configured differently".into());
                    }
                    return Ok(self.peer_confirmation(existing));
                }
                let result = self.peer_confirmation(&pending);
                self.pending_peers = Some(pending);
                Ok(result)
            }
            "frost_confirm_peers" => {
                if let Some(peers) = self.peers.as_ref() {
                    Self::verify_peer_confirmations(peers, params)?;
                    return Ok(json!({"confirmed": true}));
                }
                let pending = self
                    .pending_peers
                    .as_ref()
                    .ok_or_else(|| "FROST peer manifest is not pending".to_string())?;
                Self::verify_peer_confirmations(pending, params)?;
                let pending = self
                    .pending_peers
                    .take()
                    .expect("confirmed peer manifest remains pending");
                self.peers = Some(pending);
                self.persist()?;
                Ok(json!({"confirmed": true}))
            }
            "frost_dkg_round1" => {
                if self.frost_key.is_some() {
                    return Err("FROST group is already finalized on this node".into());
                }
                if let Some(pending) = self.dkg_round2.as_ref() {
                    return Ok(json!({
                        "party": self.config.node + 1,
                        "package": BASE64.encode(&pending.round1_package),
                    }));
                }
                if let Some(pending) = self.dkg_round1.as_ref() {
                    return Ok(json!({
                        "party": self.config.node + 1,
                        "package": BASE64.encode(&pending.broadcast_package),
                    }));
                }
                let participants = self
                    .peers
                    .as_ref()
                    .ok_or_else(|| "FROST peer manifest is not confirmed".to_string())?
                    .entries
                    .len();
                let identifier = frost::Identifier::try_from(self.config.node + 1)
                    .map_err(|_| "FROST node identifier is invalid")?;
                let (secret, package) = frost::keys::dkg::part1(
                    identifier,
                    u16::try_from(participants)
                        .map_err(|_| "FROST participant count is invalid")?,
                    u16::try_from(self.config.threshold + 1)
                        .map_err(|_| "FROST signing threshold is invalid")?,
                    OsRng,
                )
                .map_err(|_| "FROST DKG round one failed")?;
                let broadcast_package = package
                    .serialize()
                    .map_err(|_| "FROST DKG round-one serialization failed")?;
                self.dkg_round1 = Some(PendingDkgRound1 {
                    secret,
                    broadcast_package: broadcast_package.clone(),
                });
                self.persist()?;
                Ok(json!({
                    "party": self.config.node + 1,
                    "package": BASE64.encode(broadcast_package),
                }))
            }
            "frost_dkg_round2" => {
                let broadcasts_digest: [u8; 32] = Sha256::new()
                    .chain_update(b"QOMM:FROST:DKG-BROADCASTS:v1")
                    .chain_update(
                        serde_json::to_vec(
                            params
                                .get("broadcasts")
                                .ok_or_else(|| "FROST DKG broadcasts are absent".to_string())?,
                        )
                        .map_err(|error| error.to_string())?,
                    )
                    .finalize()
                    .into();
                if let Some(pending) = self.dkg_round2.as_ref() {
                    if pending.broadcasts_digest != broadcasts_digest {
                        return Err(
                            "FROST DKG round two was already persisted for another transcript"
                                .into(),
                        );
                    }
                    return Ok(json!({"encrypted": pending.encrypted.clone()}));
                }
                let peers = self
                    .peers
                    .as_ref()
                    .ok_or_else(|| "FROST peer manifest is not confirmed".to_string())?;
                let session = peers.session;
                let broadcasts = self.frost_broadcasts(params, peers)?;
                let own = frost::Identifier::try_from(self.config.node + 1)
                    .map_err(|_| "FROST node identifier is invalid")?;
                let others = broadcasts
                    .iter()
                    .filter(|(identifier, _)| **identifier != own)
                    .map(|(identifier, package)| (*identifier, package.clone()))
                    .collect::<BTreeMap<_, _>>();
                let round1 = self
                    .dkg_round1
                    .as_ref()
                    .ok_or_else(|| "FROST DKG round-one secret is absent".to_string())?;
                let own_broadcast = broadcasts
                    .get(&own)
                    .ok_or_else(|| "FROST DKG broadcasts omit this node".to_string())?
                    .serialize()
                    .map_err(|_| "FROST DKG round-one serialization failed")?;
                if own_broadcast != round1.broadcast_package {
                    return Err("FROST DKG broadcasts substituted this node's round one".into());
                }
                let secret = frost::keys::dkg::round1::SecretPackage::deserialize(
                    &round1
                        .secret
                        .serialize()
                        .map_err(|_| "FROST DKG round-one serialization failed")?,
                )
                .map_err(|_| "FROST DKG round-one secret cannot be restored")?;
                let (secret, directed) = frost::keys::dkg::part2(secret, &others)
                    .map_err(|_| "FROST DKG round two failed")?;
                let sender = self.config.node + 1;
                let mut encrypted = Vec::new();
                for recipient in 1..=u16::try_from(peers.entries.len())
                    .map_err(|_| "FROST participant count is invalid")?
                {
                    if recipient == sender {
                        continue;
                    }
                    let identifier = frost::Identifier::try_from(recipient)
                        .map_err(|_| "FROST recipient identifier is invalid")?;
                    let package = directed
                        .get(&identifier)
                        .ok_or_else(|| "FROST DKG omitted a directed package".to_string())?
                        .serialize()
                        .map_err(|_| "FROST directed package serialization failed")?;
                    let peer = &peers
                        .peers
                        .get(&recipient)
                        .ok_or_else(|| "FROST directed package names an unknown peer".to_string())?
                        .exchange;
                    let key = self.exchange_key(&session, sender, recipient, peer)?;
                    let mut nonce = [0_u8; 12];
                    OsRng.fill_bytes(&mut nonce);
                    let ciphertext = encrypt_exchange(
                        &key,
                        &nonce,
                        &package,
                        &Self::exchange_aad(&session, sender, recipient),
                    )?;
                    encrypted.push(json!({
                        "sender": sender,
                        "recipient": recipient,
                        "nonce": hex::encode(nonce),
                        "ciphertext": BASE64.encode(ciphertext),
                    }));
                }
                self.dkg_round1 = None;
                self.dkg_round2 = Some(PendingDkgRound2 {
                    secret,
                    round1_package: own_broadcast,
                    broadcasts_digest,
                    encrypted: encrypted.clone(),
                });
                self.persist()?;
                Ok(json!({"encrypted": encrypted}))
            }
            "frost_dkg_finalize" => {
                let finalize_digest: [u8; 32] = Sha256::new()
                    .chain_update(b"QOMM:FROST:DKG-FINALIZE:v1")
                    .chain_update(self.config.node.to_be_bytes())
                    .chain_update(serde_json::to_vec(params).map_err(|error| error.to_string())?)
                    .finalize()
                    .into();
                if let Some(public) = self.frost_public.as_ref() {
                    if self.frost_dkg_finalize_digest != Some(finalize_digest) {
                        return Err(
                            "FROST DKG was already finalized with another transcript".into()
                        );
                    }
                    let encoded = public
                        .serialize()
                        .map_err(|_| "FROST public key serialization failed")?;
                    return Ok(json!({"public_package": BASE64.encode(encoded)}));
                }
                let peers = self
                    .peers
                    .as_ref()
                    .ok_or_else(|| "FROST peer manifest is not confirmed".to_string())?;
                let session = peers.session;
                let broadcasts = self.frost_broadcasts(params, peers)?;
                let pending = self
                    .dkg_round2
                    .as_ref()
                    .ok_or_else(|| "FROST DKG round-two secret is absent".to_string())?;
                let broadcasts_digest: [u8; 32] = Sha256::new()
                    .chain_update(b"QOMM:FROST:DKG-BROADCASTS:v1")
                    .chain_update(
                        serde_json::to_vec(
                            params
                                .get("broadcasts")
                                .ok_or_else(|| "FROST DKG broadcasts are absent".to_string())?,
                        )
                        .map_err(|error| error.to_string())?,
                    )
                    .finalize()
                    .into();
                if broadcasts_digest != pending.broadcasts_digest {
                    return Err("FROST finalization changed the round-two broadcasts".into());
                }
                let own_party = self.config.node + 1;
                let own = frost::Identifier::try_from(own_party)
                    .map_err(|_| "FROST node identifier is invalid")?;
                let others = broadcasts
                    .iter()
                    .filter(|(identifier, _)| **identifier != own)
                    .map(|(identifier, package)| (*identifier, package.clone()))
                    .collect::<BTreeMap<_, _>>();
                let incoming = params
                    .get("incoming")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "FROST directed packages must be an array".to_string())?;
                if incoming.len() + 1 != peers.entries.len() {
                    return Err("FROST directed package set is incomplete".into());
                }
                let mut received = BTreeMap::new();
                for envelope in incoming {
                    let sender = envelope
                        .get("sender")
                        .and_then(Value::as_u64)
                        .and_then(|party| u16::try_from(party).ok())
                        .ok_or_else(|| "FROST directed sender is invalid".to_string())?;
                    let recipient = envelope
                        .get("recipient")
                        .and_then(Value::as_u64)
                        .and_then(|party| u16::try_from(party).ok())
                        .ok_or_else(|| "FROST directed recipient is invalid".to_string())?;
                    if sender == own_party || recipient != own_party {
                        return Err("FROST directed package has the wrong endpoints".into());
                    }
                    let nonce: [u8; 12] = hex::decode(
                        envelope
                            .get("nonce")
                            .and_then(Value::as_str)
                            .ok_or_else(|| "FROST directed nonce is absent".to_string())?,
                    )
                    .map_err(|_| "FROST directed nonce is malformed")?
                    .try_into()
                    .map_err(|_| "FROST directed nonce is malformed")?;
                    let ciphertext = BASE64
                        .decode(
                            envelope
                                .get("ciphertext")
                                .and_then(Value::as_str)
                                .ok_or_else(|| "FROST directed ciphertext is absent".to_string())?,
                        )
                        .map_err(|_| "FROST directed ciphertext is malformed")?;
                    let peer = &peers
                        .peers
                        .get(&sender)
                        .ok_or_else(|| "FROST directed sender is unknown".to_string())?
                        .exchange;
                    let key = self.exchange_key(&session, sender, recipient, peer)?;
                    let clear = decrypt_exchange(
                        &key,
                        &nonce,
                        &ciphertext,
                        &Self::exchange_aad(&session, sender, recipient),
                    )?
                    .ok_or_else(|| "FROST directed package authentication failed".to_string())?;
                    let identifier = frost::Identifier::try_from(sender)
                        .map_err(|_| "FROST directed sender identifier is invalid")?;
                    if received
                        .insert(
                            identifier,
                            frost::keys::dkg::round2::Package::deserialize(&clear)
                                .map_err(|_| "FROST directed package cannot be decoded")?,
                        )
                        .is_some()
                    {
                        return Err("FROST directed sender is duplicated".into());
                    }
                }
                let (key_package, public) =
                    frost::keys::dkg::part3(&pending.secret, &others, &received)
                        .map_err(|_| "FROST DKG final verification failed")?;
                let encoded = public
                    .serialize()
                    .map_err(|_| "FROST public key serialization failed")?;
                self.frost_key = Some(key_package);
                self.frost_public = Some(public);
                self.frost_session = Some(session);
                self.frost_dkg_finalize_digest = Some(finalize_digest);
                self.dkg_round2 = None;
                self.dkg_round1 = None;
                self.peers = None;
                self.pending_peers = None;
                self.persist()?;
                Ok(json!({"public_package": BASE64.encode(encoded)}))
            }
            "authorize_reserve_payment" => {
                let signing_job = Self::hex32(params.get("signing_job_id"), "signing_job_id")?;
                let message = Self::one_wire(params, "message")?;
                if message.len() != 64 {
                    return Err("reserve payment message must be one SHA-512 digest".into());
                }
                let mandate = ReserveMandate::from_params(params)?;
                let amount_commitment =
                    Self::point(params.get("amount_commitment"), "amount_commitment")?;
                let price_commitment =
                    Self::point(params.get("price_commitment"), "price_commitment")?;
                let asset_commitment =
                    Self::point(params.get("asset_commitment"), "asset_commitment")?;
                let payer_handle = Self::point(params.get("payer_handle"), "payer_handle")?;
                let payee_handle = Self::point(params.get("payee_handle"), "payee_handle")?;
                if payer_handle == payee_handle {
                    return Err("reserve payment cannot pay its owner handle".into());
                }
                let deadline = params
                    .get("deadline")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "deadline must be an unsigned timestamp".to_string())?;
                let nonce = Self::hex32(params.get("nonce"), "nonce")?;
                let quote_binding = match params.get("quote_kind").and_then(Value::as_str) {
                    Some("legacy") => QuoteBinding::LegacyPackedKey(
                        params
                            .get("quote_key")
                            .and_then(Value::as_u64)
                            .filter(|value| *value != 0)
                            .ok_or_else(|| "reserve quote key must be non-zero".to_string())?,
                    ),
                    Some("proof") => QuoteBinding::ProofDigest(Self::hex32(
                        params.get("quote_digest"),
                        "quote_digest",
                    )?),
                    _ => return Err("reserve quote binding kind is invalid".into()),
                };
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock is before the Unix epoch")?
                    .as_secs();
                if deadline < now || deadline > now.saturating_add(86_400) {
                    return Err("reserve deadline is outside the signer horizon".into());
                }
                mandate.verify_payment(&amount_commitment, &payer_handle, deadline, now)?;
                let expected = PartialInstruction::digest_public_fields_for(
                    DEFAULT_DOMAIN,
                    &amount_commitment,
                    &price_commitment,
                    &asset_commitment,
                    &payer_handle,
                    &payee_handle,
                    deadline,
                    nonce,
                    quote_binding,
                );
                if message.as_slice() != expected.as_slice() {
                    return Err("reserve payment signing request changed a signed field".into());
                }
                self.authorize_frost(signing_job, &message)?;
                Ok(json!({"authorized": true, "kind": "pretrade-reserve-payment"}))
            }
            "authorize_reserve_typed" => {
                let signing_job = Self::hex32(params.get("signing_job_id"), "signing_job_id")?;
                let message = Self::one_wire(params, "message")?;
                if message.len() != 64 {
                    return Err("typed reserve message must be one SHA-512 digest".into());
                }
                let mandate = ReserveMandate::from_params(params)?;
                let payment = payment_wire::decode(&Self::one_wire(params, "payment")?)
                    .map_err(|_| "reserve payment wire is invalid".to_string())?;
                let public = self
                    .frost_public
                    .as_ref()
                    .ok_or_else(|| "FROST key generation is incomplete".to_string())?;
                public
                    .verifying_key()
                    .verify(&payment.digest(), &payment.signature)
                    .map_err(|_| "reserve payment lacks this committee's signature".to_string())?;
                let context =
                    typed_wire::decode_context(&Self::one_wire(params, "context")?, &payment)
                        .map_err(|_| "typed reserve context wire is invalid".to_string())?;
                if context.operation != typed::OperationKind::Reserve {
                    return Err("reserve signer received a non-reserve operation".into());
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock is before the Unix epoch")?
                    .as_secs();
                mandate.verify_context(&payment, &context, now)?;
                let expected = typed::digest_for(&payment, &context, DEFAULT_DOMAIN)
                    .map_err(str::to_string)?;
                if message.as_slice() != expected.as_slice() {
                    return Err("typed reserve signing request changed its context".into());
                }
                self.authorize_frost(signing_job, &message)?;
                Ok(json!({"authorized": true, "kind": "pretrade-reserve-context"}))
            }
            "authorize_standing_pool_allocation" => {
                let proof_job = Self::job_id(params)?;
                let signing_job = Self::hex32(params.get("signing_job_id"), "signing_job_id")?;
                let message = Self::one_wire(params, "message")?;
                if message.len() != 64 {
                    return Err("standing pool signing message must be one SHA-512 digest".into());
                }
                let binding = StandingPoolAllocationBinding::from_body(
                    params
                        .get("allocation_binding")
                        .ok_or_else(|| "standing pool allocation binding is absent".to_string())?,
                )?;
                if binding.proof_job_id != proof_job
                    || binding.signing_message()?.as_slice() != message.as_slice()
                {
                    return Err(
                        "standing pool signing request changed its canonical allocation".into(),
                    );
                }
                let maker = match ReserveMandate::from_params(params)? {
                    ReserveMandate::Maker(value) => value,
                    ReserveMandate::Taker(_) => {
                        return Err("a Taker mandate cannot allocate a Maker standing pool".into())
                    }
                };
                let instruction = payment_wire::decode(&Self::one_wire(params, "payment")?)
                    .map_err(|_| "standing pool payment wire is invalid".to_string())?;
                let dvp_proofs = decode_dvp_proofs(&Self::one_wire(params, "dvp_proofs")?)?;
                let pool_remainder_proof =
                    decode_threshold_range(&Self::one_wire(params, "pool_remainder_range")?)?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock is before the Unix epoch")?
                    .as_secs();
                maker.verify_signature_at(now)?;
                let maker_mandate_digest = maker.digest()?;
                if binding.authorization.entity_commitment != maker.entity_commitment
                    || binding.authorization.asset_id != maker.asset_id
                    || binding.authorization.direction != maker.direction as u8
                    || binding.authorization.policy_digest != maker.policy_digest
                    || binding.authorization.mandate_digest != maker_mandate_digest
                    || binding.authorization.policy_version != maker.policy_version
                    || binding.pool_id
                        != standing_note_pool_id(
                            maker.entity_commitment,
                            maker.policy_digest,
                            maker_mandate_digest,
                            maker.asset_id,
                            maker.direction as u8,
                        )?
                    || binding.delegation_digest
                        != standing_note_pool_delegation_digest(
                            binding.pool_id,
                            maker.venue_id,
                            maker.defmi_id,
                            binding.committee_epoch,
                            maker.valid_until,
                        )?
                    || (binding.expected_pool_sequence == 0
                        && binding.previous_amount_commitment != maker.maximum_amount_commitment)
                {
                    return Err(
                        "standing pool allocation differs from the signed Maker mandate".into(),
                    );
                }
                let public = self
                    .frost_public
                    .as_ref()
                    .ok_or_else(|| "FROST key generation is incomplete".to_string())?;
                public
                    .verifying_key()
                    .verify(&instruction.digest(), &instruction.signature)
                    .map_err(|_| {
                        "standing pool payment lacks this committee's signature".to_string()
                    })?;
                let (
                    expected_quote_digest,
                    winning_policy_digest,
                    selected_maker_handle,
                    authorized_payment_digest,
                    maker_is_payer,
                    quantity_commitment,
                    cash_commitment,
                    securities_remainder,
                    cash_remainder,
                    securities_reserve,
                    cash_reserve,
                    pool_remainder_commitment,
                ) = {
                    let job = self.jobs.get(&proof_job).ok_or_else(|| {
                        "standing pool authorization proof job is not active".to_string()
                    })?;
                    if !job.quote_verified
                        || !job.dvp_response_issued
                        || !job.pool_remainder_response_issued
                    {
                        return Err(
                            "standing pool cannot be allocated before quote, DvP, and pool-remainder proofs"
                                .into(),
                        );
                    }
                    (
                        job.expected_quote_digest,
                        job.winning_policy_digest.ok_or_else(|| {
                            "standing pool proof has no winning policy".to_string()
                        })?,
                        job.selected_maker_handle.ok_or_else(|| {
                            "standing pool proof has no winning Maker".to_string()
                        })?,
                        job.authorized_payment_digest.ok_or_else(|| {
                            "standing pool proof has no authorized zkPI".to_string()
                        })?,
                        job.maker_is_payer.ok_or_else(|| {
                            "standing pool proof has no Maker payment side".to_string()
                        })?,
                        job.quantity_commitment.ok_or_else(|| {
                            "standing pool proof has no quantity commitment".to_string()
                        })?,
                        job.cash_commitment.ok_or_else(|| {
                            "standing pool proof has no cash commitment".to_string()
                        })?,
                        job.securities_remainder.ok_or_else(|| {
                            "standing pool proof has no securities remainder".to_string()
                        })?,
                        job.cash_remainder.ok_or_else(|| {
                            "standing pool proof has no cash remainder".to_string()
                        })?,
                        job.securities_reserve.ok_or_else(|| {
                            "standing pool proof has no securities reserve".to_string()
                        })?,
                        job.cash_reserve
                            .ok_or_else(|| "standing pool proof has no cash reserve".to_string())?,
                        job.pool_remainder_commitment.ok_or_else(|| {
                            "standing pool proof has no parent-pool remainder commitment"
                                .to_string()
                        })?,
                    )
                };
                let maker_handle = CompressedRistretto(maker.maker_handle)
                    .decompress()
                    .ok_or_else(|| "Maker mandate handle is not canonical".to_string())?;
                let expected_direction = if maker_is_payer { 2 } else { 1 };
                if maker.policy_digest != winning_policy_digest
                    || maker_handle.compress() != selected_maker_handle.compress()
                    || binding.authorization.direction != expected_direction
                    || instruction.digest() != authorized_payment_digest
                    || instruction.quote_proof_digest() != Some(expected_quote_digest)
                    || binding.quote_proof_digest != expected_quote_digest
                    || instruction.amount_commitment.compress() != quantity_commitment.compress()
                    || (maker_is_payer
                        && instruction.payer_handle.compress() != selected_maker_handle.compress())
                    || (!maker_is_payer
                        && instruction.payee_handle.compress() != selected_maker_handle.compress())
                {
                    return Err(
                        "standing pool allocation differs from the MPC-selected Maker quote".into(),
                    );
                }
                if !verify_product(
                    &self.key,
                    &mut Transcript::new(DVP_PRODUCT_CONTEXT),
                    &quantity_commitment,
                    &instruction.price_commitment,
                    &cash_commitment,
                    &dvp_proofs.product,
                ) || !verify_threshold_range(
                    &self.key,
                    &securities_remainder,
                    &dvp_proofs.securities_remainder,
                    DVP_SECURITIES_REMAINDER_CONTEXT,
                ) || !verify_threshold_range(
                    &self.key,
                    &cash_remainder,
                    &dvp_proofs.cash_remainder,
                    DVP_CASH_REMAINDER_CONTEXT,
                ) {
                    return Err("standing pool received an invalid public DvP proof".into());
                }
                let sides = threshold_dvp_sides(&instruction);
                if binding.dvp_proof_digest
                    != threshold_dvp_package_digest(
                        &instruction,
                        &sides,
                        &cash_commitment,
                        &securities_remainder,
                        &cash_remainder,
                        &dvp_proofs,
                    )
                {
                    return Err("standing pool names another DvP proof package".into());
                }
                let expected_child = if maker_is_payer {
                    cash_reserve
                } else {
                    securities_reserve
                };
                let pool_remainder = CompressedRistretto(binding.remainder_note.value_commitment)
                    .decompress()
                    .ok_or_else(|| "standing pool remainder is not canonical".to_string())?;
                if binding.escrow_note.value_commitment != expected_child.compress().to_bytes()
                    || pool_remainder.compress() != pool_remainder_commitment.compress()
                    || binding.remainder_range_proof_digest
                        != threshold_range_proof_digest(&pool_remainder_proof)
                    || !verify_threshold_range(
                        &self.key,
                        &pool_remainder,
                        &pool_remainder_proof,
                        STANDING_POOL_REMAINDER_CONTEXT,
                    )
                {
                    return Err(
                        "standing pool split differs from the proved Maker reserve or remainder"
                            .into(),
                    );
                }
                self.authorize_frost(signing_job, &message)?;
                Ok(json!({"authorized": true, "kind": "standing-pool-allocation"}))
            }
            "authorize_zkpi" => {
                let proof_job = Self::job_id(params)?;
                let signing_job = Self::hex32(params.get("signing_job_id"), "signing_job_id")?;
                let message = Self::one_wire(params, "message")?;
                if message.len() != 64 {
                    return Err("zkPI signing message must be one SHA-512 digest".into());
                }
                let amount_range =
                    decode_threshold_range(&Self::one_wire(params, "amount_range")?)?;
                let price_range = decode_threshold_range(&Self::one_wire(params, "price_range")?)?;
                let asset_commitment =
                    Self::point(params.get("asset_commitment"), "asset_commitment")?;
                let payer_handle = Self::point(params.get("payer_handle"), "payer_handle")?;
                let payee_handle = Self::point(params.get("payee_handle"), "payee_handle")?;
                let deadline = params
                    .get("deadline")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "deadline must be an unsigned timestamp".to_string())?;
                let nonce = Self::hex32(params.get("nonce"), "nonce")?;
                let quote_digest = Self::hex32(params.get("quote_digest"), "quote_digest")?;
                let (
                    amount_commitment,
                    price_commitment,
                    expected_quote_digest,
                    selected_maker_handle,
                    quote_verified,
                ) = {
                    let job = self
                        .jobs
                        .get(&proof_job)
                        .ok_or_else(|| "zkPI authorization proof job is not active".to_string())?;
                    let statements = job
                        .zkpi_statements
                        .as_ref()
                        .ok_or_else(|| "zkPI proof statement is not ready".to_string())?;
                    (
                        statements.amount.commitment,
                        statements.price.commitment,
                        job.expected_quote_digest,
                        job.selected_maker_handle.ok_or_else(|| {
                            "winning Maker handle is not bound to the zkPI job".to_string()
                        })?,
                        job.quote_verified,
                    )
                };
                if !quote_verified {
                    return Err("zkPI cannot be authorized before the complete quote proof".into());
                }
                if quote_digest != expected_quote_digest {
                    return Err("zkPI quote digest differs from the loaded MPC job".into());
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock is before the Unix epoch")?
                    .as_secs();
                if deadline < now || deadline > now.saturating_add(3_600) {
                    return Err("zkPI deadline is outside the proof-node horizon".into());
                }
                let maker_is_payer = payer_handle.compress() == selected_maker_handle.compress();
                let maker_is_payee = payee_handle.compress() == selected_maker_handle.compress();
                if maker_is_payer == maker_is_payee {
                    return Err(
                        "zkPI must bind the MPC-selected Maker to exactly one payment endpoint"
                            .into(),
                    );
                }
                let taker_handle = if maker_is_payer {
                    payee_handle
                } else {
                    payer_handle
                };
                let partial = PartialInstruction::from_threshold_ranges(
                    &self.key,
                    &Bounds {
                        amount_bits: self.config.amount_bits,
                        price_bits: self.config.price_bits,
                        max_horizon: 3_600,
                    },
                    amount_commitment,
                    price_commitment,
                    asset_commitment,
                    amount_range,
                    price_range,
                    payer_handle,
                    payee_handle,
                    deadline,
                    nonce,
                    quote_digest,
                )
                .map_err(str::to_string)?;
                if message.as_slice() != partial.digest().as_slice() {
                    return Err("FROST request is not the verified MPC-derived zkPI".into());
                }
                let payment_digest = partial.digest();
                let job = self
                    .jobs
                    .get_mut(&proof_job)
                    .ok_or_else(|| "zkPI authorization proof job is not active".to_string())?;
                match job.authorized_payment_digest {
                    Some(prior) if prior != payment_digest => {
                        return Err("proof job was rebound to another payment instruction".into())
                    }
                    Some(_) => {}
                    None => job.authorized_payment_digest = Some(payment_digest),
                }
                match (job.authorized_taker_handle, job.maker_is_payer) {
                    (Some(prior_handle), Some(prior_side))
                        if prior_handle.compress() != taker_handle.compress()
                            || prior_side != maker_is_payer =>
                    {
                        return Err(
                            "proof job was rebound to another Maker/Taker payment side".into()
                        )
                    }
                    (Some(_), Some(_)) => {}
                    (None, None) => {
                        job.authorized_taker_handle = Some(taker_handle);
                        job.maker_is_payer = Some(maker_is_payer);
                    }
                    _ => return Err("proof job has incomplete payment-side evidence".into()),
                }
                self.authorize_frost(signing_job, &message)?;
                Ok(json!({"authorized": true, "kind": "mpc-zkpi"}))
            }
            "authorize_typed" => {
                let proof_job = Self::job_id(params)?;
                let signing_job = Self::hex32(params.get("signing_job_id"), "signing_job_id")?;
                let message = Self::one_wire(params, "message")?;
                if message.len() != 64 {
                    return Err("typed zkPI signing message must be one SHA-512 digest".into());
                }
                let payment = payment_wire::decode(&Self::one_wire(params, "payment")?)
                    .map_err(|_| "typed authorization payment wire is invalid".to_string())?;
                let context =
                    typed_wire::decode_context(&Self::one_wire(params, "context")?, &payment)
                        .map_err(|_| "typed authorization context wire is invalid".to_string())?;
                if !matches!(
                    context.operation,
                    typed::OperationKind::Consume | typed::OperationKind::Settle
                ) || context.scope != typed::AuthorizationScope::Joint
                {
                    return Err("typed proof finalization must jointly settle a trade".into());
                }
                let completed = self
                    .completed_evidence
                    .get(&proof_job)
                    .cloned()
                    .ok_or_else(|| "typed authorization has no completed MPC proof".to_string())?;
                if payment.digest() != completed.payment_digest
                    || context.quote_proof_digest != completed.quote_digest
                {
                    return Err("typed authorization differs from the completed MPC quote".into());
                }
                let maker_handle = completed.maker_handle.ok_or_else(|| {
                    "completed proof predates winning-Maker settlement binding".to_string()
                })?;
                let taker_handle = completed.taker_handle.ok_or_else(|| {
                    "completed proof predates Taker settlement binding".to_string()
                })?;
                let maker_is_payer = completed.maker_is_payer.ok_or_else(|| {
                    "completed proof predates payment-side settlement binding".to_string()
                })?;
                let winning_policy_digest = completed.winning_policy_digest.ok_or_else(|| {
                    "completed proof predates winning-policy settlement binding".to_string()
                })?;
                let expected_direction = if maker_is_payer {
                    typed::TradeDirection::TakerSells
                } else {
                    typed::TradeDirection::TakerBuys
                };
                if context.maker_handle.compress().to_bytes() != maker_handle
                    || context.taker_handle.compress().to_bytes() != taker_handle
                    || context.direction != expected_direction
                {
                    return Err(
                        "typed settlement does not use the MPC-selected Maker/Taker roles".into(),
                    );
                }
                let trusted_defmi = VerifyingKey::from_bytes(
                    &self.config.trusted_defmi_receipt_public.ok_or_else(|| {
                        "proof node has no pinned DeFMI reservation receipt key".to_string()
                    })?,
                )
                .map_err(|_| "pinned DeFMI reservation receipt key is malformed".to_string())?;
                let acknowledgement = decode_ack(&Self::one_wire(params, "pretrade_ack")?)?;
                acknowledgement.verify(&trusted_defmi)?;
                if acknowledgement.defmi_id != context.defmi_id
                    || acknowledgement.after_state_root != context.before_state_root
                {
                    return Err(
                        "typed settlement is not based on the acknowledged DeFMI state".into(),
                    );
                }
                let mandate_direction = match context.direction {
                    typed::TradeDirection::TakerBuys => crate::mandate::Direction::TakerBuys,
                    typed::TradeDirection::TakerSells => crate::mandate::Direction::TakerSells,
                };
                let maker_binding = acknowledgement.binding_for(
                    ReservationParty::Maker,
                    &maker_handle,
                    mandate_direction,
                )?;
                let taker_binding = acknowledgement.binding_for(
                    ReservationParty::Taker,
                    &taker_handle,
                    mandate_direction,
                )?;
                let securities_reserve = completed.securities_reserve.ok_or_else(|| {
                    "completed proof predates securities-reserve binding".to_string()
                })?;
                let cash_reserve = completed
                    .cash_reserve
                    .ok_or_else(|| "completed proof predates cash-reserve binding".to_string())?;
                let (maker_reserve, taker_reserve) = if maker_is_payer {
                    (cash_reserve, securities_reserve)
                } else {
                    (securities_reserve, cash_reserve)
                };
                if maker_binding.reserve_id != context.maker_reservation_id
                    || maker_binding.mandate_digest != context.maker_mandate_digest
                    || maker_binding.policy_digest != context.maker_policy_digest
                    || maker_binding.policy_digest != winning_policy_digest
                    || maker_binding.reserve_receipt_digest != context.maker_reserve_receipt_digest
                    || maker_binding.amount_commitment != maker_reserve
                    || taker_binding.reserve_id != context.taker_reservation_id
                    || taker_binding.mandate_digest != context.taker_mandate_digest
                    || taker_binding.reserve_receipt_digest != context.taker_reserve_receipt_digest
                    || taker_binding.amount_commitment != taker_reserve
                {
                    return Err(
                        "typed settlement differs from the acknowledged pre-trade reserves".into(),
                    );
                }
                let public = self
                    .frost_public
                    .clone()
                    .ok_or_else(|| "FROST DKG is not complete".to_string())?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock is before the Unix epoch")?
                    .as_secs();
                Venue::new(
                    self.key.clone(),
                    &Bounds {
                        amount_bits: self.config.amount_bits,
                        price_bits: self.config.price_bits,
                        max_horizon: 3_600,
                    },
                    public,
                )
                .require_threshold_ranges()
                .verify(&payment, now)
                .map_err(|error| format!("typed authorization payment failed: {error}"))?;
                let expected = typed::digest_for(&payment, &context, DEFAULT_DOMAIN)
                    .map_err(str::to_string)?;
                if message.as_slice() != expected.as_slice() {
                    return Err("typed FROST message does not encode this execution context".into());
                }
                let message_digest: [u8; 32] = Sha256::digest(&message).into();
                match completed.typed_message_digest {
                    Some(prior) if prior != message_digest => {
                        return Err(
                            "completed MPC proof was already bound to another settlement".into(),
                        )
                    }
                    _ => {}
                }
                self.completed_evidence
                    .get_mut(&proof_job)
                    .expect("completed evidence checked above")
                    .typed_message_digest = Some(message_digest);
                self.authorize_frost(signing_job, &message)?;
                Ok(json!({"authorized": true, "kind": "typed-mpc-zkpi"}))
            }
            "sign_publication" => {
                let statement: PublicationStatement = serde_json::from_value(
                    params
                        .get("statement")
                        .cloned()
                        .ok_or_else(|| "publication statement is absent".to_string())?,
                )
                .map_err(|_| "publication statement is malformed")?;
                let sensitivity = params
                    .get("sensitivity")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        "publication sensitivity must be an unsigned integer".to_string()
                    })?;
                let support = params
                    .get("support")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or_else(|| {
                        "publication support must be an unsigned 16-bit integer".to_string()
                    })?;
                let mechanism = DpMechanism::new(statement.epsilon_micros, sensitivity, support)?;
                let evidence_path = params
                    .get("evidence_path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "publication evidence_path is absent".to_string())?;
                if self.publication_consumed.contains(&statement.operation_id) {
                    return Err("publication operation was already signed by this node".into());
                }
                let node_id = format!("node-{}", self.config.node);
                self.publication_evidence(evidence_path)?
                    .validate_for(&node_id, &statement, &mechanism)?;
                let body = statement.body()?;
                self.publication_consumed.insert(statement.operation_id);
                self.persist()?;
                let signature = self.identity.sign(&body);
                Ok(json!({
                    "node_id": node_id,
                    "identity_public": hex::encode(self.identity.verifying_key().to_bytes()),
                    "signature": hex::encode(signature.to_bytes()),
                    "operation_id": hex::encode(statement.operation_id),
                }))
            }
            "authorize_health" => {
                if !self.config.allow_health_signing {
                    return Err("health signing is disabled on this proof node".into());
                }
                let signing_job = Self::hex32(params.get("signing_job_id"), "signing_job_id")?;
                let message = Self::one_wire(params, "message")?;
                let cluster = Self::hex32(params.get("cluster_digest"), "cluster_digest")?;
                let stage = match params.get("stage").and_then(Value::as_str) {
                    Some("pre-restart") => 1_u8,
                    Some("post-restart") => 2_u8,
                    _ => return Err("health signing stage is invalid".into()),
                };
                let session = self
                    .frost_session
                    .ok_or_else(|| "FROST DKG is not complete".to_string())?;
                let expected = Sha256::new()
                    .chain_update(b"QOMM:FROST:HEALTH:v1")
                    .chain_update(session)
                    .chain_update([stage])
                    .chain_update(cluster)
                    .finalize();
                if message.as_slice() != expected.as_slice() {
                    return Err("health signing message is not domain-separated".into());
                }
                self.authorize_frost(signing_job, &message)?;
                Ok(json!({"authorized": true, "kind": "health"}))
            }
            "frost_commit" => {
                let job_id = Self::job_id(params)?;
                if self.frost_consumed.contains(&job_id)
                    || self.frost_reserved.contains(&job_id)
                    || self.frost_nonces.contains_key(&job_id)
                {
                    return Err("FROST signing job identifier was already used".into());
                }
                let message = Self::one_wire(params, "message")?;
                let message_digest: [u8; 32] = Sha256::digest(&message).into();
                if self.frost_authorized.get(&job_id) != Some(&message_digest)
                    || job_id != Self::signing_job(&message)
                {
                    return Err(
                        "FROST node will sign only a locally authorized proof output".into(),
                    );
                }
                let key = self
                    .frost_key
                    .as_ref()
                    .ok_or_else(|| "FROST DKG is not complete".to_string())?;
                let (nonces, commitments) = frost::round1::commit(key.signing_share(), &mut OsRng);
                self.frost_nonces.insert(
                    job_id,
                    FrostNonceState {
                        message_digest,
                        nonces,
                    },
                );
                self.frost_authorized.remove(&job_id);
                self.frost_reserved.insert(job_id);
                self.persist()?;
                Ok(json!({
                    "party": self.config.node + 1,
                    "commitments": BASE64.encode(commitments.serialize().map_err(|_| "FROST commitment serialization failed")?),
                }))
            }
            "frost_sign" => {
                let job_id = Self::job_id(params)?;
                let message = Self::one_wire(params, "message")?;
                let commitments = params
                    .get("commitments")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "FROST commitments must be an array".to_string())?;
                if commitments.len() < self.config.threshold + 1 || commitments.len() > 64 {
                    return Err("FROST commitment quorum is outside its bound".into());
                }
                let mut decoded = BTreeMap::new();
                for commitment in commitments {
                    let party = commitment
                        .get("party")
                        .and_then(Value::as_u64)
                        .and_then(|party| u16::try_from(party).ok())
                        .ok_or_else(|| "FROST commitment party is invalid".to_string())?;
                    let raw = BASE64
                        .decode(
                            commitment
                                .get("commitments")
                                .and_then(Value::as_str)
                                .ok_or_else(|| "FROST commitment is absent".to_string())?,
                        )
                        .map_err(|_| "FROST commitment is malformed")?;
                    let identifier = frost::Identifier::try_from(party)
                        .map_err(|_| "FROST commitment identifier is invalid")?;
                    if decoded
                        .insert(
                            identifier,
                            frost::round1::SigningCommitments::deserialize(&raw)
                                .map_err(|_| "FROST commitment cannot be decoded")?,
                        )
                        .is_some()
                    {
                        return Err("FROST commitment party is duplicated".into());
                    }
                }
                let own = frost::Identifier::try_from(self.config.node + 1)
                    .map_err(|_| "FROST node identifier is invalid")?;
                if !decoded.contains_key(&own) {
                    return Err("FROST signing package omits this node".into());
                }
                let state = self
                    .frost_nonces
                    .remove(&job_id)
                    .ok_or_else(|| "FROST nonce is absent or already consumed".to_string())?;
                self.frost_reserved.remove(&job_id);
                self.frost_consumed.insert(job_id);
                // Burn the signing job before a share leaves the node. A crash
                // after this write can lose the response, but cannot make the
                // same job signable again.
                self.persist()?;
                let message_digest: [u8; 32] = Sha256::digest(&message).into();
                if state.message_digest != message_digest {
                    return Err("FROST signing message changed after nonce commitment".into());
                }
                let package = frost::SigningPackage::new(decoded, &message);
                let share = frost::round2::sign(
                    &package,
                    &state.nonces,
                    self.frost_key
                        .as_ref()
                        .ok_or_else(|| "FROST DKG is not complete".to_string())?,
                )
                .map_err(|_| "FROST node refused its signing round")?;
                Ok(json!({
                    "party": self.config.node + 1,
                    "share": BASE64.encode(share.serialize()),
                }))
            }
            "load" => {
                let job_id = Self::job_id(params)?;
                let expected_quote_digest =
                    Self::hex32(params.get("quote_digest"), "quote_digest")?;
                if expected_quote_digest == [0_u8; 32] {
                    return Err("proof job quote digest cannot be zero".into());
                }
                if self.completed.contains(&job_id)
                    || self.reserved.contains(&job_id)
                    || self.jobs.contains_key(&job_id)
                {
                    return Err("proof job identifier was already used on this node".into());
                }
                if self.jobs.len() >= MAX_JOBS {
                    return Err("proof party has reached its active-job bound".into());
                }
                let relative = params
                    .get("persistence")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "persistence must be a relative path".to_string())?;
                let path = self.safe_persistence(relative)?;
                let persistence = fs::read(&path)
                    .map_err(|error| format!("node-local persistence cannot be hashed: {error}"))?;
                if persistence.len() > 64 << 20 {
                    return Err("node-local persistence exceeds its proof bound".into());
                }
                let persistence_digest: [u8; 32] = Sha256::digest(&persistence).into();
                let (zkpi, dvp) = if self.config.complete_quote_proof {
                    (
                        read_local_zkpi_handoff_from_quote(
                            &path,
                            self.config.node as usize,
                            self.config.n_mm,
                            self.config.amount_bits,
                            self.config.price_bits,
                            self.config.remainder_bits,
                            self.config.quote_eligibility_bits,
                            self.config.quote_span_bits,
                            -1,
                        ),
                        read_local_dvp_handoff_from_quote(
                            &path,
                            self.config.node as usize,
                            self.config.n_mm,
                            self.config.amount_bits,
                            self.config.price_bits,
                            self.config.remainder_bits,
                            self.config.quote_eligibility_bits,
                            self.config.quote_span_bits,
                            -1,
                        ),
                    )
                } else {
                    (
                        read_local_zkpi_handoff_from_dvp(
                            &path,
                            self.config.node as usize,
                            self.config.n_mm,
                            self.config.amount_bits,
                            self.config.price_bits,
                            self.config.remainder_bits,
                            -1,
                        ),
                        read_local_dvp_handoff(
                            &path,
                            self.config.node as usize,
                            self.config.n_mm,
                            self.config.amount_bits,
                            self.config.price_bits,
                            self.config.remainder_bits,
                            -1,
                        ),
                    )
                };
                let quote = if self.config.complete_quote_proof {
                    Some(
                        read_local_quote_proof_handoff(
                            &path,
                            self.config.node as usize,
                            self.config.n_mm,
                            self.config.amount_bits,
                            self.config.price_bits,
                            self.config.remainder_bits,
                            self.config.quote_eligibility_bits,
                            self.config.quote_span_bits,
                            -1,
                        )
                        .map_err(|error| error.to_string())?,
                    )
                } else {
                    None
                };
                let zkpi = zkpi.map_err(|error| error.to_string())?;
                let dvp = dvp.map_err(|error| error.to_string())?;
                let maker_handle_share = field_scalar(&zkpi.maker_handle_share)?;
                let limit = MpcLimitNode::from_handoff(zkpi.clone(), self.config.threshold)?;
                let zkpi = MpcZkpiNode::from_handoff(zkpi, self.config.threshold)?;
                let pool_remainder =
                    MpcLimitNode::from_pool_handoff(dvp.clone(), self.config.threshold)?;
                let dvp = MpcDvpNode::from_handoff(dvp, self.config.threshold)?;
                let quote = quote
                    .map(|handoff| {
                        MpcQuoteNode::from_handoff(
                            handoff,
                            (1..=self.config.n_parties).collect(),
                            self.config.threshold,
                        )
                    })
                    .transpose()?;
                if zkpi.party() != self.config.node as usize + 1
                    || limit.party() != self.config.node as usize + 1
                    || pool_remainder.party() != self.config.node as usize + 1
                    || dvp.party() != self.config.node as usize + 1
                    || quote
                        .as_ref()
                        .is_some_and(|quote| quote.party() != self.config.node as usize + 1)
                {
                    return Err("persistence handoff belongs to another proof party".into());
                }
                self.jobs.insert(
                    job_id,
                    ProofJob {
                        expected_quote_digest,
                        persistence_digest,
                        authorized_payment_digest: None,
                        authorized_taker_handle: None,
                        maker_is_payer: None,
                        maker_handle_share,
                        selected_maker_handle: None,
                        quote,
                        quote_bound: None,
                        quote_statement: None,
                        quote_relations: None,
                        quote_public: None,
                        winning_policy_digest: None,
                        quote_context: None,
                        quote_round1: None,
                        quote_verified: !self.config.complete_quote_proof,
                        zkpi: Some(zkpi),
                        zkpi_bound: None,
                        zkpi_statements: None,
                        zkpi_round1: None,
                        limit: Some(limit),
                        limit_bound: None,
                        limit_round1: None,
                        pool_remainder: Some(pool_remainder),
                        pool_remainder_bound: None,
                        pool_remainder_round1: None,
                        pool_remainder_commitment: None,
                        pool_remainder_response_issued: false,
                        dvp: Some(dvp),
                        dvp_bound: None,
                        dvp_round1: None,
                        quantity_commitment: None,
                        cash_commitment: None,
                        securities_remainder: None,
                        cash_remainder: None,
                        securities_reserve: None,
                        cash_reserve: None,
                        dvp_response_issued: false,
                    },
                );
                self.reserved.insert(job_id);
                self.persist()?;
                Ok(json!({"party": self.config.node as usize + 1}))
            }
            "maker_handle_evaluation" => {
                let job_id = Self::job_id(params)?;
                let key = self.key.clone();
                let job = self
                    .jobs
                    .get(&job_id)
                    .ok_or_else(|| "proof job is not loaded on this node".to_string())?;
                Ok(json!({
                    "party": self.config.node as usize + 1,
                    "point": hex::encode((key.g * job.maker_handle_share).compress().to_bytes()),
                }))
            }
            "quote_evaluations" => {
                let job_id = Self::job_id(params)?;
                let circuit = QuoteCircuit::try_new(
                    self.config.quote_eligibility_bits - 2,
                    self.config.quote_span_bits,
                )
                .map_err(str::to_string)?;
                let job = self.job_mut(&job_id)?;
                let node = job
                    .quote
                    .as_ref()
                    .ok_or_else(|| "complete quote evaluation phase is closed".to_string())?;
                Self::encoded_quote(
                    job_id,
                    QuoteMessage::Evaluations(node.inner().evaluations(&circuit.key)),
                )
            }
            "quote_bind" => {
                let job_id = Self::job_id(params)?;
                let evaluations = Self::decode_wires(params, "evaluations")?
                    .into_iter()
                    .map(|raw| match decode_quote(&raw)? {
                        QuoteEnvelope {
                            job_id: wire_job,
                            message: QuoteMessage::Evaluations(value),
                        } if wire_job == job_id => Ok(value),
                        _ => Err("quote bind received another job or message type".into()),
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let (public, winner_index, winner_value, context) = Self::quote_public(params)?;
                let circuit = QuoteCircuit::try_new(
                    self.config.quote_eligibility_bits - 2,
                    self.config.quote_span_bits,
                )
                .map_err(str::to_string)?;
                let parties = (1..=self.config.n_parties).collect::<Vec<_>>();
                let statement = quote_statement_from_evaluations(
                    &circuit,
                    &evaluations,
                    &public,
                    winner_index,
                    winner_value,
                    &parties,
                    self.config.threshold,
                )?;
                let winning_policy_digest = registered_policy_digest(
                    winner_index,
                    public.registry.get(winner_index).ok_or_else(|| {
                        "quote winner is outside the registered policy set".to_string()
                    })?,
                );
                let job = self.job_mut(&job_id)?;
                let node = job
                    .quote
                    .take()
                    .ok_or_else(|| "complete quote node was already bound".to_string())?
                    .into_inner()
                    .bind(&circuit.key, &statement)?;
                let relation = node.relation_evaluations(&circuit, &public)?;
                job.quote_bound = Some(node);
                job.quote_statement = Some(statement);
                job.quote_public = Some(public);
                job.winning_policy_digest = Some(winning_policy_digest);
                job.quote_context = Some(context);
                Self::encoded_quote(job_id, QuoteMessage::RelationEvaluations(relation))
            }
            "quote_relation_bind" => {
                let job_id = Self::job_id(params)?;
                let evaluations = Self::decode_wires(params, "evaluations")?
                    .into_iter()
                    .map(|raw| match decode_quote(&raw)? {
                        QuoteEnvelope {
                            job_id: wire_job,
                            message: QuoteMessage::RelationEvaluations(value),
                        } if wire_job == job_id => Ok(value),
                        _ => Err("quote relation bind received another job or message type".into()),
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let circuit = QuoteCircuit::try_new(
                    self.config.quote_eligibility_bits - 2,
                    self.config.quote_span_bits,
                )
                .map_err(str::to_string)?;
                let job = self.job_mut(&job_id)?;
                let statement = job
                    .quote_statement
                    .as_ref()
                    .ok_or_else(|| "quote base statement is not bound".to_string())?;
                let public = job
                    .quote_public
                    .as_ref()
                    .ok_or_else(|| "quote public statement is absent".to_string())?;
                let relations = quote_relation_statements_from_evaluations(
                    &circuit,
                    statement,
                    public,
                    &evaluations,
                )?;
                job.quote_relations = Some(relations);
                Ok(json!({"party": self.config.node as usize + 1, "bound": true}))
            }
            "quote_round1" => {
                let job_id = Self::job_id(params)?;
                let circuit = QuoteCircuit::try_new(
                    self.config.quote_eligibility_bits - 2,
                    self.config.quote_span_bits,
                )
                .map_err(str::to_string)?;
                let job = self.job_mut(&job_id)?;
                if job.quote_round1.is_some() {
                    return Err("quote round one was already issued for this job".into());
                }
                if job.quote_relations.is_none() {
                    return Err("quote relation statement is not bound".into());
                }
                let node = job
                    .quote_bound
                    .as_ref()
                    .ok_or_else(|| "quote node is not bound".to_string())?;
                let public = job
                    .quote_public
                    .as_ref()
                    .ok_or_else(|| "quote public statement is absent".to_string())?;
                let context = job
                    .quote_context
                    .as_deref()
                    .ok_or_else(|| "quote context is absent".to_string())?;
                let (seal, secret, round) =
                    node.prepare_round1(&circuit, public, context, &mut rand_core::OsRng)?;
                job.quote_round1 = Some(secret);
                Ok(json!({
                    "seal": Self::encoded_quote(job_id, QuoteMessage::Round1Seal(seal))?,
                    "round": Self::encoded_quote(job_id, QuoteMessage::Round1(round))?,
                }))
            }
            "quote_round2" => {
                let job_id = Self::job_id(params)?;
                let raw = Self::one_wire(params, "challenge")?;
                let challenge = match decode_quote(&raw)? {
                    QuoteEnvelope {
                        job_id: wire_job,
                        message: QuoteMessage::Challenge(value),
                    } if wire_job == job_id => value,
                    _ => return Err("quote response received another job or message type".into()),
                };
                let circuit = QuoteCircuit::try_new(
                    self.config.quote_eligibility_bits - 2,
                    self.config.quote_span_bits,
                )
                .map_err(str::to_string)?;
                let job = self.job_mut(&job_id)?;
                let secret = job.quote_round1.take().ok_or_else(|| {
                    "quote first-round secret is absent or already consumed".to_string()
                })?;
                let response = job
                    .quote_bound
                    .as_ref()
                    .ok_or_else(|| "quote node is not bound".to_string())?
                    .answer_round1(
                        &circuit,
                        job.quote_public
                            .as_ref()
                            .ok_or_else(|| "quote public statement is absent".to_string())?,
                        secret,
                        &challenge,
                    )?;
                Self::encoded_quote(job_id, QuoteMessage::Round2(response))
            }
            "quote_finalize" => {
                let job_id = Self::job_id(params)?;
                let decode_messages = |name: &str| -> Result<Vec<QuoteMessage>, String> {
                    Self::decode_wires(params, name)?
                        .into_iter()
                        .map(|raw| match decode_quote(&raw)? {
                            QuoteEnvelope {
                                job_id: wire_job,
                                message,
                            } if wire_job == job_id => Ok(message),
                            _ => Err(format!("{name} contains another quote job")),
                        })
                        .collect()
                };
                let rounds = decode_messages("rounds")?
                    .into_iter()
                    .map(|message| match message {
                        QuoteMessage::Round1(value) => Ok(value),
                        _ => Err("quote finalization received a non-round-one message".into()),
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let seals = decode_messages("seals")?
                    .into_iter()
                    .map(|message| match message {
                        QuoteMessage::Round1Seal(value) => Ok(value),
                        _ => Err("quote finalization received a non-seal message".into()),
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let responses = decode_messages("responses")?
                    .into_iter()
                    .map(|message| match message {
                        QuoteMessage::Round2(value) => Ok(value),
                        _ => Err("quote finalization received a non-response message".into()),
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let quorum = params
                    .get("quorum")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "quote quorum must be an array".to_string())?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|value| usize::try_from(value).ok())
                            .filter(|value| (1..=self.config.n_parties).contains(value))
                            .ok_or_else(|| "quote quorum party is invalid".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let circuit = QuoteCircuit::try_new(
                    self.config.quote_eligibility_bits - 2,
                    self.config.quote_span_bits,
                )
                .map_err(str::to_string)?;
                let job = self.job_mut(&job_id)?;
                if job.quote_verified {
                    return Err("quote proof was already finalized".into());
                }
                let public = job
                    .quote_public
                    .as_ref()
                    .ok_or_else(|| "quote public statement is absent".to_string())?;
                let proof = assemble_quote_from_rounds(
                    &circuit,
                    job.quote_statement
                        .as_ref()
                        .ok_or_else(|| "quote base statement is absent".to_string())?,
                    job.quote_relations
                        .as_ref()
                        .ok_or_else(|| "quote relation statement is absent".to_string())?,
                    public,
                    &rounds,
                    &seals,
                    &responses,
                    &quorum,
                    job.quote_context
                        .as_deref()
                        .ok_or_else(|| "quote context is absent".to_string())?,
                )?;
                let digest = quote_proof_digest(public, &proof);
                job.expected_quote_digest = digest;
                job.quote_verified = true;
                Ok(
                    json!({"party": self.config.node as usize + 1, "quote_digest": hex::encode(digest)}),
                )
            }
            "zkpi_evaluations" => {
                let job_id = Self::job_id(params)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                let node = job
                    .zkpi
                    .as_ref()
                    .ok_or_else(|| "zkPI evaluation phase is closed".to_string())?;
                Self::encoded_zkpi(job_id, ZkpiMessage::Evaluations(node.evaluations(&key)))
            }
            "zkpi_bind" => {
                let job_id = Self::job_id(params)?;
                let evaluations = Self::decode_wires(params, "evaluations")?
                    .into_iter()
                    .map(
                        |raw| match decode_zkpi(&raw).map_err(|error| error.to_string())? {
                            ZkpiEnvelope {
                                job_id: wire_job,
                                message: ZkpiMessage::Evaluations(value),
                            } if wire_job == job_id => Ok(value),
                            _ => Err("zkPI bind received another job or message type".into()),
                        },
                    )
                    .collect::<Result<Vec<_>, String>>()?;
                let statements = zkpi_statements(&evaluations, self.config.threshold)?;
                let key = self.key.clone();
                let handle_values = params
                    .get("maker_handle_evaluations")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        "maker_handle_evaluations must be the fixed committee array".to_string()
                    })?;
                if handle_values.len() != self.config.n_parties {
                    return Err("winning Maker handle omitted a configured proof party".into());
                }
                let mut handle_evaluations = BTreeMap::new();
                for entry in handle_values {
                    let party = entry
                        .get("party")
                        .and_then(Value::as_u64)
                        .and_then(|value| usize::try_from(value).ok())
                        .ok_or_else(|| {
                            "winning Maker handle has an invalid party identifier".to_string()
                        })?;
                    if !(1..=self.config.n_parties).contains(&party)
                        || handle_evaluations
                            .insert(
                                party,
                                Self::point(entry.get("point"), "maker handle evaluation")?,
                            )
                            .is_some()
                    {
                        return Err(
                            "winning Maker handle has a missing or duplicate committee party"
                                .into(),
                        );
                    }
                }
                let selected_maker_handle = coefficient_commitments_from_evaluations(
                    &handle_evaluations,
                    self.config.threshold,
                )?
                .first()
                .copied()
                .ok_or_else(|| "winning Maker handle coefficient ladder is empty".to_string())?;
                if selected_maker_handle == RistrettoPoint::default() {
                    return Err("winning Maker handle is the identity point".into());
                }
                let own_party = self.config.node as usize + 1;
                let own_evaluation = {
                    let job = self
                        .jobs
                        .get(&job_id)
                        .ok_or_else(|| "proof job is not loaded on this node".to_string())?;
                    key.g * job.maker_handle_share
                };
                if handle_evaluations
                    .get(&own_party)
                    .map(RistrettoPoint::compress)
                    != Some(own_evaluation.compress())
                {
                    return Err("coordinator changed this node's Maker handle evaluation".into());
                }
                let job = self.job_mut(&job_id)?;
                let node = job
                    .zkpi
                    .take()
                    .ok_or_else(|| "zkPI node was already bound".to_string())?
                    .bind(&key, &statements)?;
                let relation = node.relation_evaluations(&key);
                job.selected_maker_handle = Some(selected_maker_handle);
                job.zkpi_statements = Some(statements);
                job.zkpi_bound = Some(node);
                Self::encoded_zkpi(job_id, ZkpiMessage::RelationEvaluations(relation))
            }
            "zkpi_round1" => {
                let job_id = Self::job_id(params)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                if job.zkpi_round1.is_some() {
                    return Err("zkPI round one was already issued for this job".into());
                }
                let node = job
                    .zkpi_bound
                    .as_ref()
                    .ok_or_else(|| "zkPI node is not bound".to_string())?;
                let (seal, secret, round) = node.prepare_round1(&key, &mut rand_core::OsRng);
                job.zkpi_round1 = Some(secret);
                Ok(json!({
                    "seal": Self::encoded_zkpi(job_id, ZkpiMessage::Round1Seal(seal))?,
                    "round": Self::encoded_zkpi(job_id, ZkpiMessage::Round1(round))?,
                }))
            }
            "zkpi_round2" => {
                let job_id = Self::job_id(params)?;
                let raw = Self::one_wire(params, "challenge")?;
                let challenge = match decode_zkpi(&raw).map_err(|error| error.to_string())? {
                    ZkpiEnvelope {
                        job_id: wire_job,
                        message: ZkpiMessage::Challenge(value),
                    } if wire_job == job_id => value,
                    _ => return Err("zkPI response received another job or message type".into()),
                };
                let job = self.job_mut(&job_id)?;
                let secret = job.zkpi_round1.take().ok_or_else(|| {
                    "zkPI first-round secret is absent or already consumed".to_string()
                })?;
                let response = job
                    .zkpi_bound
                    .as_ref()
                    .ok_or_else(|| "zkPI node is not bound".to_string())?
                    .answer(secret, &challenge)?;
                Self::encoded_zkpi(job_id, ZkpiMessage::Round2(response))
            }
            "limit_evaluations" => {
                let job_id = Self::job_id(params)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                let node = job
                    .limit
                    .as_ref()
                    .ok_or_else(|| "hidden-limit evaluation phase is closed".to_string())?;
                Self::encoded_limit(job_id, LimitMessage::Evaluations(node.evaluations(&key)))
            }
            "limit_bind" => {
                let job_id = Self::job_id(params)?;
                let evaluations = Self::decode_wires(params, "evaluations")?
                    .into_iter()
                    .map(|raw| match decode_limit(&raw)? {
                        LimitEnvelope {
                            job_id: wire_job,
                            message: LimitMessage::Evaluations(value),
                        } if wire_job == job_id => Ok(value),
                        _ => Err("hidden-limit bind received another job or message type".into()),
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let statement = limit_statement(&evaluations, self.config.threshold)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                let node = job
                    .limit
                    .take()
                    .ok_or_else(|| "hidden-limit node was already bound".to_string())?
                    .bind(&key, &statement)?;
                let relation = node.relation_evaluations(&key);
                job.limit_bound = Some(node);
                Self::encoded_limit(job_id, LimitMessage::RelationEvaluations(relation))
            }
            "limit_round1" => {
                let job_id = Self::job_id(params)?;
                let context = Self::hex32(params.get("context"), "context")?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                if job.limit_round1.is_some() {
                    return Err("hidden-limit round one was already issued for this job".into());
                }
                let node = job
                    .limit_bound
                    .as_ref()
                    .ok_or_else(|| "hidden-limit node is not bound".to_string())?;
                let (seal, secret, round) =
                    node.prepare_round1(&key, &context, &mut rand_core::OsRng);
                job.limit_round1 = Some(secret);
                Ok(json!({
                    "seal": Self::encoded_limit(job_id, LimitMessage::Round1Seal(seal))?,
                    "round": Self::encoded_limit(job_id, LimitMessage::Round1(round))?,
                }))
            }
            "limit_round2" => {
                let job_id = Self::job_id(params)?;
                let raw = Self::one_wire(params, "challenge")?;
                let challenge = match decode_limit(&raw)? {
                    LimitEnvelope {
                        job_id: wire_job,
                        message: LimitMessage::Challenge(value),
                    } if wire_job == job_id => value,
                    _ => {
                        return Err(
                            "hidden-limit response received another job or message type".into()
                        )
                    }
                };
                let job = self.job_mut(&job_id)?;
                let secret = job.limit_round1.take().ok_or_else(|| {
                    "hidden-limit first-round secret is absent or already consumed".to_string()
                })?;
                let response = job
                    .limit_bound
                    .as_ref()
                    .ok_or_else(|| "hidden-limit node is not bound".to_string())?
                    .answer(secret, &challenge)?;
                Self::encoded_limit(job_id, LimitMessage::Round2(response))
            }
            "pool_remainder_evaluations" => {
                let job_id = Self::job_id(params)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                let node = job.pool_remainder.as_ref().ok_or_else(|| {
                    "standing-pool remainder evaluation phase is closed".to_string()
                })?;
                Self::encoded_limit(job_id, LimitMessage::Evaluations(node.evaluations(&key)))
            }
            "pool_remainder_bind" => {
                let job_id = Self::job_id(params)?;
                let evaluations = Self::decode_wires(params, "evaluations")?
                    .into_iter()
                    .map(|raw| match decode_limit(&raw)? {
                        LimitEnvelope {
                            job_id: wire_job,
                            message: LimitMessage::Evaluations(value),
                        } if wire_job == job_id => Ok(value),
                        _ => Err(
                            "standing-pool remainder bind received another job or message type"
                                .into(),
                        ),
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let statement = limit_statement(&evaluations, self.config.threshold)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                let node = job
                    .pool_remainder
                    .take()
                    .ok_or_else(|| "standing-pool remainder node was already bound".to_string())?
                    .bind(&key, &statement)?;
                let relation = node.relation_evaluations(&key);
                job.pool_remainder_commitment = Some(statement.commitment);
                job.pool_remainder_bound = Some(node);
                Self::encoded_limit(job_id, LimitMessage::RelationEvaluations(relation))
            }
            "pool_remainder_round1" => {
                let job_id = Self::job_id(params)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                if job.pool_remainder_round1.is_some() {
                    return Err(
                        "standing-pool remainder round one was already issued for this job".into(),
                    );
                }
                let node = job
                    .pool_remainder_bound
                    .as_ref()
                    .ok_or_else(|| "standing-pool remainder node is not bound".to_string())?;
                let (seal, secret, round) = node.prepare_round1(
                    &key,
                    STANDING_POOL_REMAINDER_CONTEXT,
                    &mut rand_core::OsRng,
                );
                job.pool_remainder_round1 = Some(secret);
                Ok(json!({
                    "seal": Self::encoded_limit(job_id, LimitMessage::Round1Seal(seal))?,
                    "round": Self::encoded_limit(job_id, LimitMessage::Round1(round))?,
                }))
            }
            "pool_remainder_round2" => {
                let job_id = Self::job_id(params)?;
                let raw = Self::one_wire(params, "challenge")?;
                let challenge =
                    match decode_limit(&raw)? {
                        LimitEnvelope {
                            job_id: wire_job,
                            message: LimitMessage::Challenge(value),
                        } if wire_job == job_id => value,
                        _ => return Err(
                            "standing-pool remainder response received another job or message type"
                                .into(),
                        ),
                    };
                let job = self.job_mut(&job_id)?;
                let secret = job.pool_remainder_round1.take().ok_or_else(|| {
                    "standing-pool remainder first-round secret is absent or already consumed"
                        .to_string()
                })?;
                let response = job
                    .pool_remainder_bound
                    .as_ref()
                    .ok_or_else(|| "standing-pool remainder node is not bound".to_string())?
                    .answer(secret, &challenge)?;
                job.pool_remainder_response_issued = true;
                Self::encoded_limit(job_id, LimitMessage::Round2(response))
            }
            "dvp_evaluations" => {
                let job_id = Self::job_id(params)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                let quantity = job
                    .zkpi_statements
                    .as_ref()
                    .ok_or_else(|| "zkPI statements are not ready".to_string())?
                    .amount
                    .commitment;
                let node = job
                    .dvp
                    .as_ref()
                    .ok_or_else(|| "DvP evaluation phase is closed".to_string())?;
                Self::encoded_dvp(
                    job_id,
                    DvpMessage::Evaluations(node.evaluations(&key, &quantity)),
                )
            }
            "dvp_bind" => {
                let job_id = Self::job_id(params)?;
                let evaluations = Self::decode_wires(params, "evaluations")?
                    .into_iter()
                    .map(
                        |raw| match decode_dvp(&raw).map_err(|error| error.to_string())? {
                            DvpEnvelope {
                                job_id: wire_job,
                                message: DvpMessage::Evaluations(value),
                            } if wire_job == job_id => Ok(value),
                            _ => Err("DvP bind received another job or message type".into()),
                        },
                    )
                    .collect::<Result<Vec<_>, String>>()?;
                let constant =
                    |values: BTreeMap<usize, RistrettoPoint>| -> Result<RistrettoPoint, String> {
                        coefficient_commitments_from_evaluations(&values, self.config.threshold)?
                            .first()
                            .copied()
                            .ok_or_else(|| "empty DvP coefficient ladder".into())
                    };
                let cash = constant(
                    evaluations
                        .iter()
                        .map(|node| (node.party, node.product.relation))
                        .collect(),
                )?;
                let securities_remainder = constant(
                    evaluations
                        .iter()
                        .map(|node| (node.party, node.securities_remainder.value))
                        .collect(),
                )?;
                let cash_remainder = constant(
                    evaluations
                        .iter()
                        .map(|node| (node.party, node.cash_remainder.value))
                        .collect(),
                )?;
                let key = self.key.clone();
                let threshold = self.config.threshold;
                let job = self.job_mut(&job_id)?;
                let zkpi = job
                    .zkpi_statements
                    .as_ref()
                    .ok_or_else(|| "zkPI statements are not ready".to_string())?;
                let statements = dvp_statements(
                    &zkpi.amount.commitment,
                    &zkpi.price.commitment,
                    &cash,
                    &securities_remainder,
                    &cash_remainder,
                    &evaluations,
                    threshold,
                )?;
                let node = job
                    .dvp
                    .take()
                    .ok_or_else(|| "DvP node was already bound".to_string())?
                    .bind(&key, &statements)?;
                let relation = node.relation_evaluations(&key);
                job.quantity_commitment = Some(zkpi.amount.commitment);
                job.cash_commitment = Some(cash);
                job.securities_remainder = Some(securities_remainder);
                job.cash_remainder = Some(cash_remainder);
                job.securities_reserve = Some(zkpi.amount.commitment + securities_remainder);
                job.cash_reserve = Some(cash + cash_remainder);
                job.dvp_bound = Some(node);
                Self::encoded_dvp(job_id, DvpMessage::RelationEvaluations(relation))
            }
            "dvp_round1" => {
                let job_id = Self::job_id(params)?;
                let key = self.key.clone();
                let job = self.job_mut(&job_id)?;
                if job.dvp_round1.is_some() {
                    return Err("DvP round one was already issued for this job".into());
                }
                let quantity = job
                    .quantity_commitment
                    .as_ref()
                    .ok_or_else(|| "DvP quantity commitment is absent".to_string())?;
                let node = job
                    .dvp_bound
                    .as_ref()
                    .ok_or_else(|| "DvP node is not bound".to_string())?;
                let (seal, secret, round) =
                    node.prepare_round1(&key, quantity, &mut rand_core::OsRng);
                job.dvp_round1 = Some(secret);
                Ok(json!({
                    "seal": Self::encoded_dvp(job_id, DvpMessage::Round1Seal(seal))?,
                    "round": Self::encoded_dvp(job_id, DvpMessage::Round1(round))?,
                }))
            }
            "dvp_round2" => {
                let job_id = Self::job_id(params)?;
                let raw = Self::one_wire(params, "challenge")?;
                let challenge = match decode_dvp(&raw).map_err(|error| error.to_string())? {
                    DvpEnvelope {
                        job_id: wire_job,
                        message: DvpMessage::Challenge(value),
                    } if wire_job == job_id => value,
                    _ => return Err("DvP response received another job or message type".into()),
                };
                let job = self.job_mut(&job_id)?;
                let secret = job.dvp_round1.take().ok_or_else(|| {
                    "DvP first-round secret is absent or already consumed".to_string()
                })?;
                let response = job
                    .dvp_bound
                    .as_ref()
                    .ok_or_else(|| "DvP node is not bound".to_string())?
                    .answer(secret, &challenge)?;
                job.dvp_response_issued = true;
                Self::encoded_dvp(job_id, DvpMessage::Round2(response))
            }
            "claim_opening_share" => {
                let job_id = Self::job_id(params)?;
                let leg = params
                    .get("leg")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "claim opening leg is absent".to_string())?;
                let recipient_view = Self::point(params.get("recipient_view"), "recipient_view")?;
                let job = self
                    .jobs
                    .get(&job_id)
                    .ok_or_else(|| "claim opening proof job is not active".to_string())?;
                if job.authorized_payment_digest.is_none()
                    || !job.dvp_response_issued
                    || !job.pool_remainder_response_issued
                    || job.zkpi_round1.is_some()
                    || job.limit_round1.is_some()
                    || job.pool_remainder_round1.is_some()
                    || job.dvp_round1.is_some()
                    || job.quote_round1.is_some()
                {
                    return Err(
                        "claim opening is unavailable before authorization and completed proof rounds"
                            .into(),
                    );
                }
                let maker = job
                    .selected_maker_handle
                    .ok_or_else(|| "claim opening Maker handle is absent".to_string())?;
                let taker = job
                    .authorized_taker_handle
                    .ok_or_else(|| "claim opening Taker handle is absent".to_string())?;
                let maker_is_payer = job
                    .maker_is_payer
                    .ok_or_else(|| "claim opening payment side is absent".to_string())?;
                let expected_recipient = match (leg, maker_is_payer) {
                    ("securities_delivery", true) | ("securities_refund", false) => maker,
                    ("securities_delivery", false) | ("securities_refund", true) => taker,
                    ("cash_delivery", true) | ("cash_refund", false) => taker,
                    ("cash_delivery", false) | ("cash_refund", true) => maker,
                    _ => return Err("claim opening leg is invalid".into()),
                };
                if recipient_view.compress() != expected_recipient.compress() {
                    return Err(
                        "proof node refuses to encrypt a claim opening for another recipient"
                            .into(),
                    );
                }
                let (value_share, blinding_share) = match leg {
                    "securities_delivery" => job
                        .zkpi_bound
                        .as_ref()
                        .ok_or_else(|| "zkPI node is not bound".to_string())?
                        .amount_opening_share(),
                    "securities_refund" => job
                        .dvp_bound
                        .as_ref()
                        .ok_or_else(|| "DvP node is not bound".to_string())?
                        .securities_remainder_opening_share(),
                    "cash_delivery" => job
                        .dvp_bound
                        .as_ref()
                        .ok_or_else(|| "DvP node is not bound".to_string())?
                        .cash_opening_share()?,
                    "cash_refund" => job
                        .dvp_bound
                        .as_ref()
                        .ok_or_else(|| "DvP node is not bound".to_string())?
                        .cash_remainder_opening_share(),
                    _ => unreachable!("claim opening leg was validated above"),
                };
                let encrypted = encrypt_opening_share(
                    opening_context(&job_id, leg)?,
                    self.config.node as usize + 1,
                    value_share,
                    blinding_share,
                    &recipient_view,
                    &mut OsRng,
                )?;
                Ok(json!({
                    "party": encrypted.party,
                    "context": hex::encode(opening_context(&job_id, leg)?),
                    "recipient_view": hex::encode(recipient_view.compress().to_bytes()),
                    "ephemeral": hex::encode(encrypted.ephemeral.compress().to_bytes()),
                    "masked_value": hex::encode(encrypted.masked_value.to_bytes()),
                    "masked_blinding": hex::encode(encrypted.masked_blinding.to_bytes()),
                }))
            }
            "sign_admission_attestation" => {
                let slot = params
                    .get("slot")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "admission slot must be an unsigned integer".to_string())?;
                let sequence = params
                    .get("sequence")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "admission sequence must be an unsigned integer".to_string())?;
                let principal = params
                    .get("principal")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "admission principal must be a string".to_string())?;
                let ticket_id = Self::hex32(params.get("ticket_id"), "ticket_id")?;
                let claim_digest = Self::hex32(params.get("claim_digest"), "claim_digest")?;
                let batch_digest = Self::hex32(params.get("batch_digest"), "batch_digest")?;
                let order_digest = Self::hex32(params.get("order_digest"), "order_digest")?;
                let (attestation, identity_public) = self.sign_admission_attestation(
                    slot,
                    sequence,
                    principal,
                    ticket_id,
                    claim_digest,
                    batch_digest,
                    order_digest,
                )?;
                Ok(json!({
                    "node": attestation.node,
                    "slot": attestation.slot,
                    "sequence": attestation.sequence,
                    "principal_digest": hex::encode(attestation.principal_digest),
                    "ticket_id": hex::encode(attestation.ticket_id),
                    "claim_digest": hex::encode(attestation.claim_digest),
                    "batch_digest": hex::encode(attestation.batch_digest),
                    "order_digest": hex::encode(attestation.order_digest),
                    "identity_public": hex::encode(identity_public),
                    "signature": hex::encode(attestation.signature.to_bytes()),
                }))
            }
            "sign_execution_attestation" => {
                let job_id = Self::job_id(params)?;
                let batch_digest = Self::hex32(params.get("batch_digest"), "batch_digest")?;
                let source_digest = Self::hex32(params.get("source_digest"), "source_digest")?;
                let stdout_digest = Self::hex32(params.get("stdout_digest"), "stdout_digest")?;
                let stderr_digest = Self::hex32(params.get("stderr_digest"), "stderr_digest")?;
                let slot = params
                    .get("slot")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "execution slot must be an unsigned integer".to_string())?;
                let lane = params
                    .get("lane")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "execution lane must be an unsigned integer".to_string())?;
                let state_generation = params
                    .get("state_generation")
                    .and_then(Value::as_u64)
                    .filter(|value| *value != 0)
                    .ok_or_else(|| "execution generation must be positive".to_string())?;
                let frame_count = params
                    .get("frame_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "execution frame count must be unsigned".to_string())?;
                let input_count = params
                    .get("input_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "execution input count must be unsigned".to_string())?;
                let persistence_digest = self
                    .jobs
                    .get(&job_id)
                    .ok_or_else(|| "execution attestation proof job is not active".to_string())?
                    .persistence_digest;
                let mut attestation = NodeExecutionAttestation {
                    node: self.config.node,
                    slot,
                    lane,
                    batch_digest,
                    source_digest,
                    state_generation,
                    frame_count,
                    input_count,
                    stdout_digest,
                    stderr_digest,
                    persistence_digest,
                    receipt_digest: [0_u8; 32],
                    signature: Signature::from_bytes(&[0_u8; 64]),
                };
                attestation.receipt_digest = attestation.recompute_receipt_digest()?;
                let attestation = attestation.sign(&self.identity)?;
                Ok(json!({
                    "identity_public": hex::encode(self.identity.verifying_key().to_bytes()),
                    "wire": BASE64.encode(encode_node_execution_attestation(&attestation)?),
                }))
            }
            "complete" => {
                let job_id = Self::job_id(params)?;
                if self.completed_evidence.len() >= MAX_COMPLETED_EVIDENCE
                    && !self.completed_evidence.contains_key(&job_id)
                {
                    return Err("completed proof evidence has reached its retention bound".into());
                }
                let job = self
                    .jobs
                    .remove(&job_id)
                    .ok_or_else(|| "proof job is not active".to_string())?;
                if job.zkpi_round1.is_some()
                    || job.limit_round1.is_some()
                    || job.pool_remainder_round1.is_some()
                    || job.dvp_round1.is_some()
                    || job.quote_round1.is_some()
                {
                    self.jobs.insert(job_id, job);
                    return Err("proof job still has an unanswered first round".into());
                }
                if job.authorized_payment_digest.is_none()
                    || !job.dvp_response_issued
                    || !job.pool_remainder_response_issued
                {
                    self.jobs.insert(job_id, job);
                    return Err(
                        "proof job cannot complete before zkPI, DvP, and standing-pool remainder proofs"
                            .into(),
                    );
                }
                self.reserved.remove(&job_id);
                self.completed.insert(job_id);
                if let Some(payment_digest) = job.authorized_payment_digest {
                    self.completed_evidence.insert(
                        job_id,
                        CompletedProof {
                            payment_digest,
                            quote_digest: job.expected_quote_digest,
                            winning_policy_digest: job.winning_policy_digest,
                            typed_message_digest: None,
                            maker_handle: job
                                .selected_maker_handle
                                .map(|handle| handle.compress().to_bytes()),
                            taker_handle: job
                                .authorized_taker_handle
                                .map(|handle| handle.compress().to_bytes()),
                            maker_is_payer: job.maker_is_payer,
                            securities_reserve: job
                                .securities_reserve
                                .map(|value| value.compress().to_bytes()),
                            cash_reserve: job.cash_reserve.map(|value| value.compress().to_bytes()),
                        },
                    );
                }
                self.persist()?;
                Ok(json!({"completed": true}))
            }
            // Four nodes contribute VSS evaluations and verify the complete
            // quote but deliberately do not consume one-use proof/FROST
            // nonces. Only the configured 3-of-7 signing quorum can satisfy
            // `complete`; observers close through this separate fail-closed
            // operation so their durable job identifiers cannot be reused.
            "complete_observer" => {
                let job_id = Self::job_id(params)?;
                if self.completed.contains(&job_id) {
                    return Ok(json!({
                        "observer_completed": true,
                        "already_completed": true,
                    }));
                }
                let job = self
                    .jobs
                    .remove(&job_id)
                    .ok_or_else(|| "observer proof job is not active".to_string())?;
                if job.zkpi_round1.is_some()
                    || job.limit_round1.is_some()
                    || job.pool_remainder_round1.is_some()
                    || job.dvp_round1.is_some()
                    || job.quote_round1.is_some()
                {
                    self.jobs.insert(job_id, job);
                    return Err("observer proof job still has an unanswered first round".into());
                }
                if job.authorized_payment_digest.is_some()
                    || job.dvp_response_issued
                    || job.pool_remainder_response_issued
                {
                    self.jobs.insert(job_id, job);
                    return Err(
                        "a signing proof job cannot be closed through the observer path".into(),
                    );
                }
                if !job.quote_verified
                    || job.zkpi_bound.is_none()
                    || job.zkpi_statements.is_none()
                    || job.limit_bound.is_none()
                    || job.dvp_bound.is_none()
                    || job.pool_remainder_bound.is_none()
                {
                    self.jobs.insert(job_id, job);
                    return Err(
                        "observer proof job did not participate in every public proof phase".into(),
                    );
                }
                self.reserved.remove(&job_id);
                self.completed.insert(job_id);
                self.persist()?;
                Ok(json!({
                    "observer_completed": true,
                    "already_completed": false,
                }))
            }
            "health" => {
                let frost_public_package_sha256 = self
                    .frost_public
                    .as_ref()
                    .map(|public| {
                        public
                            .serialize()
                            .map(|raw| hex::encode(Sha256::digest(raw)))
                            .map_err(|_| "FROST public package serialization failed".to_string())
                    })
                    .transpose()?;
                Ok(json!({
                    "node": self.config.node,
                    "instance_id": hex::encode(self.instance_id()),
                    "security_configuration_digest": hex::encode(self.config.security_digest()),
                    "protocol_version": 1,
                    "n_mm": self.config.n_mm,
                    "n_parties": self.config.n_parties,
                    "threshold": self.config.threshold,
                    "amount_bits": self.config.amount_bits,
                    "price_bits": self.config.price_bits,
                    "remainder_bits": self.config.remainder_bits,
                    "complete_quote_proof": self.config.complete_quote_proof,
                    "quote_eligibility_bits": self.config.quote_eligibility_bits,
                    "quote_span_bits": self.config.quote_span_bits,
                    "active_jobs": self.jobs.len(),
                    "reserved_jobs": self.reserved.len(),
                    "completed_jobs": self.completed.len(),
                    "frost_ready": self.frost_key.is_some(),
                    "frost_session": self.active_frost_session().map(hex::encode),
                    "frost_peer_manifest_persisted": self.peers.is_some(),
                    "frost_dkg_round1_persisted": self.dkg_round1.is_some(),
                    "frost_dkg_round2_persisted": self.dkg_round2.is_some(),
                    "frost_public_package_sha256": frost_public_package_sha256,
                    "frost_reserved_jobs": self.frost_reserved.len(),
                    "frost_consumed_jobs": self.frost_consumed.len(),
                    "frost_authorized_jobs": self.frost_authorized.len(),
                    "state_generation": self.state_generation,
                }))
            }
            _ => Err("unknown proof-party operation".into()),
        }
    }
}

/// Serve bounded newline-delimited JSON on already-authenticated streams.
/// Production deployments wrap these streams in the node service's mutual
/// TLS channel; the acceptance runner uses an OS child process pipe.
pub fn read_bounded_request_line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|error| error.to_string())?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err("proof-party request ended before its newline".into())
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(take) > MAX_REQUEST_BYTES {
            return Err("proof-party request exceeds its fixed bound".into());
        }
        let terminated = available[take - 1] == b'\n';
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if terminated {
            return Ok(Some(line));
        }
    }
}

pub fn encode_bounded_response(response: &ProofResponse) -> Result<Vec<u8>, String> {
    let encoded = serde_json::to_vec(response).map_err(|error| error.to_string())?;
    if encoded.len().saturating_add(1) > MAX_RESPONSE_BYTES {
        return Err("proof-party response exceeds its fixed bound".into());
    }
    Ok(encoded)
}

pub fn serve<R: BufRead, W: Write>(
    party: &mut ProofParty,
    mut reader: R,
    mut writer: W,
) -> Result<(), String> {
    loop {
        let Some(line) = read_bounded_request_line(&mut reader)? else {
            return Ok(());
        };
        let request: ProofRequest = serde_json::from_slice(&line)
            .map_err(|_| "proof-party request is not valid JSON".to_string())?;
        let response = party.handle(request);
        let encoded = encode_bounded_response(&response)?;
        writer
            .write_all(&encoded)
            .map_err(|error| error.to_string())?;
        writer.write_all(b"\n").map_err(|error| error.to_string())?;
        writer.flush().map_err(|error| error.to_string())?;
    }
}

#[cfg(test)]
mod bounded_request_tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn request_reader_never_buffers_past_its_fixed_limit() {
        let mut valid = BufReader::with_capacity(3, Cursor::new(b"{}\nnext".to_vec()));
        assert_eq!(
            read_bounded_request_line(&mut valid).unwrap().unwrap(),
            b"{}\n"
        );
        let mut partial = BufReader::new(Cursor::new(b"{}".to_vec()));
        assert!(read_bounded_request_line(&mut partial)
            .unwrap_err()
            .contains("newline"));
        let mut oversized =
            BufReader::with_capacity(1024, Cursor::new(vec![b'x'; MAX_REQUEST_BYTES + 1]));
        assert!(read_bounded_request_line(&mut oversized)
            .unwrap_err()
            .contains("fixed bound"));
    }

    #[test]
    fn response_encoder_rejects_an_oversized_record_before_writing() {
        let response = ProofResponse {
            id: 1,
            ok: true,
            result: Some(Value::String("x".repeat(MAX_RESPONSE_BYTES))),
            error: None,
        };
        assert!(encode_bounded_response(&response)
            .unwrap_err()
            .contains("fixed bound"));
    }
}
