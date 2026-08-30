//! Seven real mutually-authenticated listeners with one durable-node restart.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use merlin::Transcript;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use qomm_dsl::registry::CircuitRegistry;
use qomm_mpc::compiler::OfficialCompiler;
use qomm_mpc::inputs::{
    build_inputs, parse_policies, DvpInputs, InputConfig, Policy, QuoteProofInputs,
    QUOTE_POLICY_BLINDING_FIELDS,
};
use qomm_mpc::program::{
    build_program, policy_rule_source, sentinel_for, CheckMode, ProgramConfig, Reference,
    StopAfter, ED25519_ORDER, POLICY_RULE_NAME,
};
use qomm_proofs::kyb::{cohort_id, present, KybCredential, KybIssuer, KybPresentation};
use qomm_proofs::opening_envelope::{opening_context, EncryptedOpeningShare, OpeningEnvelope};
use qomm_proofs::price_limit::{
    from_threshold as threshold_price_limit, threshold_context as price_limit_context,
    PriceLimitDirection,
};
use qomm_proofs::quote_proof::{
    registered_policy_digest, registry_digest, Public as QuotePublic, QuoteCircuit,
    RegisteredPolicy,
};
use qomm_proofs::threshold_gadgets::coefficient_commitments_from_evaluations;
use qomm_proofs::threshold_quote::{
    assemble_quote_from_rounds, make_quote_challenges, quote_relation_statements_from_evaluations,
    quote_statement_from_evaluations, QuoteChallengeTranscript,
};
use qomm_proofs::threshold_range::verify_threshold_range;
use qomm_transport::dvp_issuer::{
    assemble_proofs as assemble_dvp_proofs, make_challenge as make_dvp_challenge,
    relation_statements_from_evaluations as dvp_relation_statements,
    statements_from_evaluations as dvp_statements, DVP_CASH_REMAINDER_CONTEXT, DVP_PRODUCT_CONTEXT,
    DVP_SECURITIES_REMAINDER_CONTEXT,
};
use qomm_transport::dvp_wire::{
    decode as decode_dvp, encode as encode_dvp, Envelope as DvpEnvelope, Message as DvpMessage,
};
use qomm_transport::executor::{
    circuit_shape_digest, write_source_bound_runtime_executable, ProgramRegistry,
    RegisteredProgram, RuntimeBinding,
};
use qomm_transport::external_kyb::{
    read_external_kyb_bundle, read_external_kyb_trust_anchor, VerifiedExternalKyb,
};
use qomm_transport::key_management::{
    create_ca, issue_mutual_tls_certificate, write_tls_bundle, EncryptedKeyStore, KeyKind,
};
use qomm_transport::limit_issuer::{
    assemble as assemble_limit, challenge as make_limit_challenge,
    relation_from_evaluations as limit_relations, statement_from_evaluations as limit_statement,
};
use qomm_transport::limit_wire::{
    decode as decode_limit, encode as encode_limit, Envelope as LimitEnvelope,
    Message as LimitMessage,
};
use qomm_transport::mandate::{Direction, MakerPolicyMandate, TakerExecutionMandate};
use qomm_transport::node_service::{
    certificate_fingerprint, client_ssl_context, server_ssl_context, KybPolicy, NodeSealingKeys,
    NodeStore, Principal, RateLimitPolicy, ResidentNodeClient, ResidentNodeLocalClient,
    ResidentNodeServer,
};
use qomm_transport::order::{
    admission_principal_digest, cluster_batch_digest, complete_quote_context, live_proof_job_id,
    principal_ticket_id, verify_admission_lane, verify_execution_lane, NodeAdmissionAttestation,
    NodeExecutionAttestation,
};
use qomm_transport::pretrade_authority::{
    encode_ack, read_ack_private, write_authority_private, AcceptanceOpening,
    MakerPretradeAuthority, PretradeAdmission, PretradeAuthorityBundle, PretradeSettlementVerifier,
    ReservationParty, TakerPretradeAuthority,
};
use qomm_transport::proof_codec::{encode_threshold_range, QuoteVerificationBundle};
use qomm_transport::proof_party::{
    serve as serve_proof_party, ProofParty, ProofPartyConfig, ProofRequest, ProofResponse,
};
use qomm_transport::quote_wire::{
    decode as decode_quote, encode as encode_quote, Envelope as QuoteEnvelope,
    Message as QuoteMessage,
};
use qomm_transport::resident_mpc::{EncryptedMpcStateStore, MpcSecretState, ResidentMpcConfig};
use qomm_transport::rfq_frame::{ResidentRfqCatalogBinding, ResidentRfqInput, ResidentRfqOpenings};
use qomm_transport::settlement_finalization::read_private as read_finalization_contexts;
use qomm_transport::settlement_handoff::{
    read_private as read_settlement_handoff, write_private as write_settlement_handoff,
    SettlementHandoff, SettlementHandoffBundle,
};
use qomm_transport::wire::{Frame, FRAME_BYTES};
use qomm_transport::zkpi_issuer::{
    assemble_ranges, build_partial_instruction, make_challenge as make_zkpi_challenge,
    relation_statements_from_evaluations as zkpi_relation_statements,
    statements_from_evaluations as zkpi_statements,
};
use qomm_transport::zkpi_wire::{
    decode as decode_zkpi, encode as encode_zkpi, Envelope as ZkpiEnvelope, Message as ZkpiMessage,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::verify_product;
use qomm_zkpi::{
    asset_scalar, frost, typed, typed_wire, Bounds, Instruction, PartialInstruction, QuoteBinding,
    Venue, DEFAULT_DOMAIN,
};
use rand_core::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const N_CLIENTS: usize = 4;
const MAKER_SECURITIES: [(u64, u64); 4] = [(100, 13), (110, 17), (120, 19), (130, 23)];
const MAKER_CASH: [(u64, u64); 4] = [
    (2_000_000, 29),
    (2_100_000, 31),
    (2_200_000, 37),
    (2_300_000, 41),
];
const TAKER_SECURITIES: (u64, u64) = (100, 7);
const TAKER_CASH: (u64, u64) = (2_000_000, 11);

fn acceptance_defmi_receipt_public() -> [u8; 32] {
    let seed: [u8; 32] = Sha256::digest(b"QOMM:ACCEPTANCE:DEFMI-RECEIPT-KEY:v1").into();
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        if std::env::var_os("QOMM_KEEP_ACCEPTANCE_ROOT").is_none() {
            let _ = fs::remove_dir_all(&self.0);
        } else {
            eprintln!("kept acceptance root: {}", self.0.display());
        }
    }
}

#[derive(Clone)]
struct Bundle {
    key: PathBuf,
    cert: PathBuf,
    ca: PathBuf,
    der: Vec<u8>,
}

#[derive(Clone)]
struct ClientIdentity {
    bundle: Bundle,
    fingerprint: String,
    frame_key: Vec<u8>,
    scope_nullifier: RistrettoPoint,
    presentation: KybPresentation,
}

struct NodeKeyStore {
    store: EncryptedKeyStore,
    authority_key_id: String,
    beacon_key_id: String,
    receipt_key_id: String,
}

impl NodeKeyStore {
    fn create(root: &Path, node: usize, now: u64) -> Result<Self, String> {
        let passphrase = Sha256::new()
            .chain_update(b"qomm-seven-node-test-keystore-v1")
            .chain_update((node as u64).to_be_bytes())
            .finalize()
            .to_vec();
        let store = EncryptedKeyStore::new(
            root.join(format!("node-{node}-sealing-keys.qks")),
            &passphrase,
        )?;
        store.initialize()?;
        let lifetime = 3650 * 24 * 60 * 60;
        let authority_key_id = store.generate(
            "admission-authority",
            KeyKind::Ed25519,
            now,
            lifetime,
            BTreeMap::new(),
        )?;
        let beacon_key_id = store.generate(
            "ordering-beacon",
            KeyKind::Ed25519,
            now,
            lifetime,
            BTreeMap::new(),
        )?;
        let receipt_key_id = store.generate(
            "node-receipt",
            KeyKind::Ed25519,
            now,
            lifetime,
            BTreeMap::new(),
        )?;
        Ok(Self {
            store,
            authority_key_id,
            beacon_key_id,
            receipt_key_id,
        })
    }

    fn load(&self, now: u64) -> Result<NodeSealingKeys, String> {
        NodeSealingKeys::from_encrypted_store(
            &self.store,
            &self.authority_key_id,
            &self.beacon_key_id,
            &self.receipt_key_id,
            now,
        )
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Tcp,
    Local,
}

enum ClusterClient {
    Tcp(ResidentNodeClient),
    Local(ResidentNodeLocalClient),
}

impl ClusterClient {
    fn call(&mut self, request: &Value) -> Result<Value, String> {
        match self {
            Self::Tcp(client) => client.call(request),
            Self::Local(client) => client.call(request),
        }
    }

    fn close(&mut self) {
        match self {
            Self::Tcp(client) => client.close(),
            Self::Local(client) => client.close(),
        }
    }
}

fn issue(
    root: &Path,
    name: &str,
    ca_key: &PKey<Private>,
    ca_cert: &X509,
) -> Result<Bundle, String> {
    let (key, cert) =
        issue_mutual_tls_certificate(ca_key, ca_cert, name, &[name], &["127.0.0.1"], 30)?;
    let der = cert.to_der().map_err(|error| error.to_string())?;
    let (key, certificate, ca) = write_tls_bundle(root.join(name), name, &key, &cert, ca_cert)?;
    Ok(Bundle {
        key,
        cert: certificate,
        ca,
        der,
    })
}

struct PreparedMpc {
    registries: Vec<Arc<ProgramRegistry>>,
    shape_digest: String,
    source_digest: String,
    quote_policies: Vec<QuotePolicyFixture>,
    quote_registry: Vec<RegisteredPolicy>,
    quote_registry_digest: [u8; 32],
    quote_reference_price: i64,
    quote_now: i64,
    quote_sentinel: i64,
    quote_market_digest: [u8; 32],
}

#[derive(Clone)]
struct QuotePolicyFixture {
    asset: u32,
    ask_level: i64,
    spread: i64,
    slope: i64,
    invcoef: i64,
    inv: i64,
    maxqty: i64,
    expiry: i64,
    active: bool,
    use_ref: bool,
}

fn signed_scalar(value: i64) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs())
    } else {
        Scalar::from(value as u64)
    }
}

fn quote_policy_fixtures(now: i64) -> Vec<QuotePolicyFixture> {
    vec![
        QuotePolicyFixture {
            asset: 0,
            ask_level: -8,
            spread: 24,
            slope: 1,
            invcoef: 1,
            inv: 4,
            maxqty: 500,
            expiry: now + 600,
            active: true,
            use_ref: true,
        },
        QuotePolicyFixture {
            asset: 0,
            ask_level: 3,
            spread: 18,
            slope: 2,
            invcoef: 1,
            inv: -3,
            maxqty: 200,
            expiry: now + 500,
            active: true,
            use_ref: true,
        },
        QuotePolicyFixture {
            asset: 0,
            ask_level: 11,
            spread: 31,
            slope: 1,
            invcoef: 2,
            inv: 5,
            maxqty: 100,
            expiry: now + 400,
            active: true,
            use_ref: true,
        },
        QuotePolicyFixture {
            asset: 0,
            ask_level: -2,
            spread: 15,
            slope: 3,
            invcoef: 1,
            inv: 1,
            maxqty: 50,
            expiry: now + 300,
            active: true,
            use_ref: true,
        },
    ]
}

fn quote_policy_json(policies: &[QuotePolicyFixture]) -> String {
    serde_json::to_string(
        &policies
            .iter()
            .map(|policy| {
                json!({
                    "asset": policy.asset,
                    "ask_level": policy.ask_level,
                    "spread": policy.spread,
                    "slope": policy.slope,
                    "invcoef": policy.invcoef,
                    "inv": policy.inv,
                    "maxqty": policy.maxqty,
                    "expiry": policy.expiry,
                    "active": u8::from(policy.active),
                    "use_ref": u8::from(policy.use_ref),
                })
            })
            .collect::<Vec<_>>(),
    )
    .expect("quote policy fixture is JSON")
}

fn product_program_config() -> ProgramConfig {
    ProgramConfig {
        n_mm: 4,
        n_parties: 7,
        mode: qomm_mpc::program::Mode::Rfq,
        n_requests: 1,
        n_assets: 1,
        ref_table: vec![100_000],
        maker_assets: vec![0; 4],
        public_maker_assets: true,
        bit_length: 31,
        binding_limit: true,
        stop_after: StopAfter::Tournament,
        persist_wires: true,
        persist_zkpi_wires: true,
        persist_quote_proof_wires: true,
        persist_dvp_wires: true,
        zkpi_amount_bits: 16,
        zkpi_price_bits: 32,
        dvp_remainder_bits: 32,
        quote_eligibility_bits: 34,
        quote_span_bits: 32,
        reference: Reference::Anchored,
        ..ProgramConfig::default()
    }
}

fn digest_file(path: &Path) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(
        fs::read(path).map_err(|error| error.to_string())?,
    )))
}

fn free_mpc_ports() -> Result<(u16, Vec<TcpListener>), String> {
    for base in (34_000_u16..60_000).step_by(13) {
        let mut listeners = Vec::new();
        let mut ok = true;
        for offset in 0..7_u16 {
            match TcpListener::bind(("127.0.0.1", base + offset)) {
                Ok(listener) => listeners.push(listener),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Ok((base, listeners));
        }
    }
    Err("no free seven-port block for stock MP-SPDZ".into())
}

fn program_artifacts(root: &Path, program: &str) -> Result<BTreeMap<String, String>, String> {
    let mut files = vec![
        format!("Programs/Source/{program}.mpc"),
        format!("Programs/Schedules/{program}.sch"),
    ];
    let bytecode = root.join("Programs/Bytecode");
    for entry in fs::read_dir(&bytecode).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("{program}-")) && name.ends_with(".bc") {
            files.push(format!("Programs/Bytecode/{name}"));
        }
    }
    files.sort();
    files
        .into_iter()
        .map(|relative| digest_file(&root.join(&relative)).map(|digest| (relative, digest)))
        .collect()
}

fn player_data_artifacts(root: &Path, node: u16) -> Result<BTreeMap<String, String>, String> {
    let directory = root.join("Player-Data");
    let mut files = fs::read_dir(&directory)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| {
            name == &format!("P{node}.key")
                || name.starts_with('P') && name.ends_with(".pem")
                || name.len() == 10 && name.ends_with(".0")
        })
        .collect::<Vec<_>>();
    files.sort();
    files
        .into_iter()
        .map(|name| digest_file(&directory.join(&name)).map(|digest| (name, digest)))
        .collect()
}

fn prepare_real_mpc(
    root: &Path,
    mp_spdz_root: &Path,
    runner: &Path,
) -> Result<PreparedMpc, String> {
    let mp_spdz_root = fs::canonicalize(mp_spdz_root).map_err(|error| error.to_string())?;
    let runner = fs::canonicalize(runner).map_err(|error| error.to_string())?;
    let config = product_program_config();
    let source = build_program(&config).map_err(|error| error.to_string())?;
    let source_digest = hex::encode(Sha256::digest(source.as_bytes()));
    let program = format!("qomm_resident_{}", &source_digest[..16]);
    let source_path = mp_spdz_root
        .join("Programs/Source")
        .join(format!("{program}.mpc"));
    fs::write(&source_path, &source).map_err(|error| error.to_string())?;
    let compiler =
        OfficialCompiler::from_checkout(&mp_spdz_root).map_err(|error| error.to_string())?;
    let compiled = compiler
        .compile_field(253, &program)
        .map_err(|error| error.to_string())?;
    if !compiled.status.success() {
        return Err(format!(
            "resident MPC circuit compilation failed: {}{}",
            String::from_utf8_lossy(&compiled.stdout),
            String::from_utf8_lossy(&compiled.stderr)
        ));
    }
    let artifacts = program_artifacts(&mp_spdz_root, &program)?;
    let (port_base, port_guards) = free_mpc_ports()?;
    let host_file = root.join("qomm-mpc-hosts");
    let hosts = (0..7)
        .map(|party| format!("127.0.0.1:{}\n", port_base + party))
        .collect::<String>();
    fs::write(&host_file, hosts).map_err(|error| error.to_string())?;
    drop(port_guards);

    let ref_table = [100_000_i128];
    let quote_now = i64::try_from(config.now_t).map_err(|_| "quote time exceeds i64")?;
    let quote_policies = quote_policy_fixtures(quote_now);
    let policy_json = quote_policy_json(&quote_policies);
    let policies: Vec<Policy> = parse_policies(&policy_json).map_err(|error| error.to_string())?;
    let maker_policy_blindings = (0..4)
        .map(|maker| {
            std::array::from_fn(|field| {
                1_000_i128 + (maker * QUOTE_POLICY_BLINDING_FIELDS + field) as i128
            })
        })
        .collect::<Vec<_>>();
    let input_config = InputConfig {
        n_mm: 4,
        n_real_mm: 4,
        n_parties: 7,
        is_real: 1,
        n_requests: 1,
        n_assets: 1,
        ref_table: &ref_table,
        user_asset: 0,
        user_qty: 10,
        user_dir: 1,
        user_entity: 42,
        now_t: config.now_t,
        seed: 0x51_4f_4d_4d,
        audit_gates: false,
        value_bits: 32,
        field_bits: 253,
        use_ref: 1,
        reference: Reference::Anchored,
        input_check: false,
        check_mode: CheckMode::Aggregate,
        binding_limit: true,
        user_limit: 0,
        user_limit_blinding: 101,
        user_qty_blinding: 151,
        check_coefficients: &[],
        check_repeats: config.check_repeats,
        policies: Some(&policies),
        shamir_inputs: false,
        shamir_threshold: 2,
        dvp: Some(DvpInputs {
            taker_securities_reserve: i128::from(TAKER_SECURITIES.0),
            taker_securities_blinding: i128::from(TAKER_SECURITIES.1),
            taker_cash_reserve: i128::from(TAKER_CASH.0),
            taker_cash_blinding: i128::from(TAKER_CASH.1),
            maker_securities_reserves: MAKER_SECURITIES
                .iter()
                .map(|value| i128::from(value.0))
                .collect(),
            maker_securities_blindings: MAKER_SECURITIES
                .iter()
                .map(|value| i128::from(value.1))
                .collect(),
            maker_cash_reserves: MAKER_CASH.iter().map(|value| i128::from(value.0)).collect(),
            maker_cash_blindings: MAKER_CASH.iter().map(|value| i128::from(value.1)).collect(),
            maker_handle_scalars: vec![21, 22, 23, 24],
        }),
        quote_proof: Some(QuoteProofInputs {
            maker_policy_blindings: maker_policy_blindings.clone(),
        }),
    };
    let generated = build_inputs(&input_config).map_err(|error| error.to_string())?;
    let quote_key = Pedersen::new(b"qomm:policy:v1");
    let quote_registry = quote_policies
        .iter()
        .zip(&maker_policy_blindings)
        .map(|(policy, blindings)| RegisteredPolicy {
            maker_asset: policy.asset,
            ask_level: quote_key.commit(
                &signed_scalar(policy.ask_level),
                &Scalar::from(blindings[0] as u64),
            ),
            spread: quote_key.commit(
                &signed_scalar(policy.spread),
                &Scalar::from(blindings[1] as u64),
            ),
            slope: quote_key.commit(
                &signed_scalar(policy.slope),
                &Scalar::from(blindings[2] as u64),
            ),
            invcoef: quote_key.commit(
                &signed_scalar(policy.invcoef),
                &Scalar::from(blindings[3] as u64),
            ),
            inv: quote_key.commit(
                &signed_scalar(policy.inv),
                &Scalar::from(blindings[4] as u64),
            ),
            maxqty: quote_key.commit(
                &signed_scalar(policy.maxqty),
                &Scalar::from(blindings[5] as u64),
            ),
            expiry: quote_key.commit(
                &signed_scalar(policy.expiry),
                &Scalar::from(blindings[6] as u64),
            ),
            active: quote_key.commit(
                &Scalar::from(u64::from(policy.active)),
                &Scalar::from(blindings[7] as u64),
            ),
            use_ref: quote_key.commit(
                &Scalar::from(u64::from(policy.use_ref)),
                &Scalar::from(blindings[8] as u64),
            ),
        })
        .collect::<Vec<_>>();
    let quote_registry_digest = registry_digest(&quote_registry);
    let quote_sentinel = i64::try_from(
        sentinel_for(config.bit_length, config.n_mm, 8 * ref_table[0])
            .map_err(|error| error.to_string())?,
    )
    .map_err(|_| "quote sentinel exceeds i64")?;
    let quote_market_digest: [u8; 32] = Sha256::new()
        .chain_update(b"QOMM:ACCEPTANCE:REFERENCE-MARKET:v1")
        .chain_update(ref_table[0].to_be_bytes())
        .chain_update(config.now_t.to_be_bytes())
        .finalize()
        .into();
    let party_inputs = generated.party_files();
    let shape = [4_u64, 7, 31];
    let shape_digest = circuit_shape_digest(&shape);
    let mut circuits = CircuitRegistry::default();
    let policy_rule = policy_rule_source(&config);
    circuits
        .approve(POLICY_RULE_NAME, &policy_rule, &source, &shape)
        .map_err(|error| error.to_string())?;
    let party_binary = fs::canonicalize(mp_spdz_root.join("malicious-shamir-party.x"))
        .map_err(|error| error.to_string())?;
    let library =
        fs::canonicalize(mp_spdz_root.join("libSPDZ.so")).map_err(|error| error.to_string())?;
    let runner_digest = digest_file(&runner)?;
    let party_digest = digest_file(&party_binary)?;
    let library_digest = digest_file(&library)?;
    let host_digest = digest_file(&host_file)?;
    fs::create_dir_all(root.join("mpc-runs")).map_err(|error| error.to_string())?;

    let mut registries = Vec::with_capacity(7);
    for node in 0..7_u16 {
        let player_data_artifacts = player_data_artifacts(&mp_spdz_root, node)?;
        let tokens = party_inputs[usize::from(node)]
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let dvp_values = DvpInputs::value_count(4);
        let maker_dvp_start = 6 + 4;
        let maker_dvp_end = 6 + dvp_values;
        // Limit value, limit blinding, fill mask, and the Taker's pre-signed
        // quantity blinding follow node-local DvP shares in the request.
        let policy_start = maker_dvp_end + 4;
        let policy_end = policy_start + 4 * 10;
        let quote_end = policy_end + 4 * QUOTE_POLICY_BLINDING_FIELDS;
        if tokens.len() != quote_end {
            return Err(format!(
                "generated party {node} input has {} values, expected {}",
                tokens.len(),
                quote_end,
            ));
        }
        // Passphrase readers accept the usual newline-terminated text-secret
        // files and therefore strip trailing CR/LF.  Persisting raw random
        // bytes here made a state store undecryptable whenever its last random
        // byte happened to be 0x0a or 0x0d.  Hex is unambiguous across initial
        // creation, process restart, and operator-managed secret files.
        let mut passphrase_entropy = [0_u8; 32];
        rand_core::OsRng.fill_bytes(&mut passphrase_entropy);
        let mut passphrase = hex::encode(passphrase_entropy).into_bytes();
        let passphrase_file = root.join(format!("node-{node}-mpc-passphrase"));
        fs::write(&passphrase_file, &passphrase).map_err(|error| error.to_string())?;
        fs::set_permissions(&passphrase_file, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        let state_store = root.join(format!("node-{node}-mpc-state.qms"));
        EncryptedMpcStateStore::new(&state_store, &passphrase)?.initialize(&MpcSecretState {
            version: 1,
            node,
            generation: 1,
            source_sha256: source_digest.clone(),
            dvp_input_shares: tokens[maker_dvp_start..maker_dvp_end].to_vec(),
            policy_input_shares: tokens[policy_start..policy_end].to_vec(),
            quote_policy_blinding_input_shares: tokens[policy_end..quote_end].to_vec(),
        })?;
        passphrase_entropy.fill(0);
        passphrase.fill(0);
        let runtime_config = ResidentMpcConfig {
            version: 1,
            node,
            n_parties: 7,
            threshold: 2,
            n_mm: 4,
            mp_spdz_root: mp_spdz_root.clone(),
            player_data_root: mp_spdz_root.join("Player-Data"),
            run_root: root.join("mpc-runs"),
            program: program.clone(),
            source_sha256: source_digest.clone(),
            host_file: host_file.clone(),
            host_file_sha256: host_digest.clone(),
            party_binary: party_binary.clone(),
            party_binary_sha256: party_digest.clone(),
            library: library.clone(),
            library_sha256: library_digest.clone(),
            player_data_artifacts,
            program_artifacts: artifacts.clone(),
            state_store,
            passphrase_file,
            prime: ED25519_ORDER.into(),
            timeout_seconds: 120.0,
        };
        let runtime_config_path = root.join(format!("node-{node}-mpc-runtime.json"));
        fs::write(
            &runtime_config_path,
            serde_json::to_vec_pretty(&runtime_config).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        fs::set_permissions(&runtime_config_path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        let runtime = RuntimeBinding {
            executable: runner.clone(),
            executable_sha256: runner_digest.clone(),
            config: runtime_config_path.clone(),
            config_sha256: digest_file(&runtime_config_path)?,
        };
        let launcher = root.join(format!("node-{node}-approved-compute"));
        write_source_bound_runtime_executable(&launcher, &source, &runtime)?;
        let launcher = fs::canonicalize(launcher).map_err(|error| error.to_string())?;
        let program_registration = RegisteredProgram {
            shape_digest: shape_digest.clone(),
            argv: vec![
                launcher.display().to_string(),
                "{node}".into(),
                "{slot}".into(),
                "{batch_digest}".into(),
                "{lane}".into(),
            ],
            cwd: root.to_path_buf(),
            executable_sha256: digest_file(&launcher)?,
            runtime: Some(runtime),
            timeout_seconds: 180.0,
        };
        registries.push(Arc::new(ProgramRegistry::from_approved_mpc(
            node,
            program_registration,
            &circuits,
            &config,
            &shape,
        )?));
    }
    Ok(PreparedMpc {
        registries,
        shape_digest,
        source_digest,
        quote_policies,
        quote_registry_digest,
        quote_registry,
        quote_reference_price: i64::try_from(ref_table[0])
            .map_err(|_| "quote reference price exceeds i64")?,
        quote_now,
        quote_sentinel,
        quote_market_digest,
    })
}

fn cross_zkpi(job_id: [u8; 32], message: ZkpiMessage) -> Result<ZkpiMessage, String> {
    let raw = encode_zkpi(&ZkpiEnvelope { job_id, message })
        .map_err(|error| format!("zkPI public wire encode failed: {error:?}"))?;
    let decoded =
        decode_zkpi(&raw).map_err(|error| format!("zkPI public wire decode failed: {error:?}"))?;
    if decoded.job_id != job_id {
        return Err("zkPI public message crossed into another job".into());
    }
    Ok(decoded.message)
}

fn cross_quote(job_id: [u8; 32], message: QuoteMessage) -> Result<QuoteMessage, String> {
    let raw = encode_quote(&QuoteEnvelope { job_id, message })?;
    let decoded = decode_quote(&raw)?;
    if decoded.job_id != job_id {
        return Err("quote public message crossed into another job".into());
    }
    Ok(decoded.message)
}

fn quote_winner(
    prepared: &PreparedMpc,
    quantity: i64,
    direction: u8,
) -> Result<(usize, u64), String> {
    let mut keys = Vec::with_capacity(prepared.quote_policies.len());
    for (index, policy) in prepared.quote_policies.iter().enumerate() {
        let anchor = policy
            .ask_level
            .checked_add(if policy.use_ref {
                prepared.quote_reference_price
            } else {
                0
            })
            .ok_or("quote anchor overflow")?;
        let depth = policy
            .slope
            .checked_mul(quantity)
            .ok_or("quote depth overflow")?;
        let skew = policy
            .invcoef
            .checked_mul(policy.inv)
            .ok_or("quote skew overflow")?;
        let ask = anchor
            .checked_add(depth)
            .and_then(|value| value.checked_add(skew))
            .ok_or("quote ask overflow")?;
        let bid = anchor
            .checked_sub(policy.spread)
            .and_then(|value| value.checked_sub(depth))
            .and_then(|value| value.checked_add(skew))
            .ok_or("quote bid overflow")?;
        let eligible = policy.asset == 0
            && policy.active
            && quantity <= policy.maxqty
            && policy.expiry > prepared.quote_now;
        let cost = if eligible {
            if direction == 1 {
                bid.checked_neg().ok_or("quote sell cost overflow")?
            } else {
                ask
            }
        } else {
            prepared.quote_sentinel
        };
        let ranked = cost
            .checked_add(prepared.quote_sentinel)
            .ok_or("ranked quote cost overflow")?;
        let key = ranked
            .checked_mul(prepared.quote_policies.len() as i64)
            .and_then(|value| value.checked_add(index as i64))
            .ok_or("quote key overflow")?;
        let key = u64::try_from(key)
            .map_err(|_| "quote sentinel does not cover the signed quote cost")?;
        keys.push(key);
    }
    let winner = (0..keys.len())
        .min_by_key(|index| keys[*index])
        .ok_or("quote registry is empty")?;
    Ok((winner, keys[winner]))
}

fn quote_public_json(
    prepared: &PreparedMpc,
    quantity: i64,
    quantity_blinding: u64,
    direction: u8,
    winner_index: usize,
    winner_value: u64,
    slot: u64,
) -> Value {
    let key = Pedersen::new(b"qomm:policy:v1");
    let registry = prepared
        .quote_registry
        .iter()
        .map(|policy| {
            json!({
                "maker_asset": policy.maker_asset,
                "ask_level": hex::encode(policy.ask_level.compress().to_bytes()),
                "spread": hex::encode(policy.spread.compress().to_bytes()),
                "slope": hex::encode(policy.slope.compress().to_bytes()),
                "invcoef": hex::encode(policy.invcoef.compress().to_bytes()),
                "inv": hex::encode(policy.inv.compress().to_bytes()),
                "maxqty": hex::encode(policy.maxqty.compress().to_bytes()),
                "expiry": hex::encode(policy.expiry.compress().to_bytes()),
                "active": hex::encode(policy.active.compress().to_bytes()),
                "use_ref": hex::encode(policy.use_ref.compress().to_bytes()),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "qty_commitment": hex::encode(key.commit(&signed_scalar(quantity), &Scalar::from(quantity_blinding)).compress().to_bytes()),
        "now": prepared.quote_now,
        "sentinel": prepared.quote_sentinel,
        "n_slots": prepared.quote_policies.len() as i64,
        "direction": direction,
        "asset": 0,
        "reference_price": prepared.quote_reference_price,
        "registry": registry,
        "registry_digest": hex::encode(prepared.quote_registry_digest),
        "market_digest": hex::encode(prepared.quote_market_digest),
        "slot": slot,
        "winner_index": winner_index,
        "winner_value": winner_value,
    })
}

fn cross_dvp(job_id: [u8; 32], message: DvpMessage) -> Result<DvpMessage, String> {
    let raw = encode_dvp(&DvpEnvelope { job_id, message })
        .map_err(|error| format!("DvP public wire encode failed: {error:?}"))?;
    let decoded =
        decode_dvp(&raw).map_err(|error| format!("DvP public wire decode failed: {error:?}"))?;
    if decoded.job_id != job_id {
        return Err("DvP public message crossed into another job".into());
    }
    Ok(decoded.message)
}

struct ProofPartyChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl ProofPartyChild {
    fn spawn(node: u16, root: &Path) -> Result<Self, String> {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let node_state = root.join("proof-parties").join(format!("node-{node}"));
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
            .map_err(|error| format!("failed to start proof party {node}: {error}"))?;
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
        self.next_id = self.next_id.saturating_add(1);
        let request = ProofRequest {
            id,
            method: method.to_string(),
            params,
        };
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| "proof-party process is already closed".to_string())?;
        serde_json::to_writer(&mut *stdin, &request).map_err(|error| error.to_string())?;
        stdin.write_all(b"\n").map_err(|error| error.to_string())?;
        stdin.flush().map_err(|error| error.to_string())?;
        let mut line = String::new();
        if self
            .stdout
            .read_line(&mut line)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Err("proof-party process closed without a response".into());
        }
        if line.len() > 8 << 20 {
            return Err("proof-party response exceeded its fixed bound".into());
        }
        let response: ProofResponse =
            serde_json::from_str(&line).map_err(|_| "proof-party returned invalid JSON")?;
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

    fn finish(mut self) -> Result<(), String> {
        self.stdin.take();
        let status = self.child.wait().map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("proof-party process exited with {status}"))
        }
    }
}

fn node_local_passphrase(root: &Path, configured: &Path) -> Result<Vec<u8>, String> {
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let parent = configured
        .parent()
        .ok_or_else(|| "proof-party passphrase path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
    if !parent.starts_with(&root) {
        return Err("proof-party passphrase must stay below its node-local root".into());
    }
    let path = parent.join(
        configured
            .file_name()
            .ok_or_else(|| "proof-party passphrase path has no file name".to_string())?,
    );
    if !path.exists() {
        let mut secret = [0_u8; 32];
        rand_core::OsRng.fill_bytes(&mut secret);
        let mut encoded = hex::encode(secret).into_bytes();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.write_all(&encoded)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        secret.fill(0);
        encoded.fill(0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("proof-party passphrase must be a private regular file".into());
    }
    let mut secret = Vec::new();
    fs::File::open(path)
        .and_then(|mut file| file.read_to_end(&mut secret))
        .map_err(|error| error.to_string())?;
    if !(16..=4096).contains(&secret.len()) {
        return Err("proof-party passphrase has an invalid length".into());
    }
    Ok(secret)
}

fn public_wire(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    let raw = BASE64
        .decode(
            value
                .as_str()
                .ok_or_else(|| format!("proof-party {name} is not a public wire"))?,
        )
        .map_err(|_| format!("proof-party {name} is not valid base64"))?;
    if raw.is_empty() || raw.len() > 1 << 20 {
        return Err(format!("proof-party {name} exceeds its fixed bound"));
    }
    Ok(raw)
}

fn wire_array(wires: &[Vec<u8>]) -> Value {
    Value::Array(
        wires
            .iter()
            .map(|wire| Value::String(BASE64.encode(wire)))
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_complete_quote(
    prepared: &PreparedMpc,
    proof_parties: &mut [ProofPartyChild],
    job_id: [u8; 32],
    quantity: i64,
    quantity_blinding: u64,
    direction: u8,
    slot: u64,
    request_context: [u8; 32],
) -> Result<QuoteVerificationBundle, String> {
    let quorum = vec![1_usize, 4, 7];
    if proof_parties.len() != 7 || direction > 1 {
        return Err("complete quote acceptance requires seven nodes and a valid direction".into());
    }
    let (winner_index, winner_value) = quote_winner(prepared, quantity, direction)?;
    let quote_key = Pedersen::new(b"qomm:policy:v1");
    let public = QuotePublic {
        qty_commitment: quote_key
            .commit(&signed_scalar(quantity), &Scalar::from(quantity_blinding)),
        now: prepared.quote_now,
        sentinel: prepared.quote_sentinel,
        n_slots: prepared.quote_policies.len() as i64,
        direction,
        asset: 0,
        reference_price: prepared.quote_reference_price,
        registry: prepared.quote_registry.clone(),
        registry_digest: prepared.quote_registry_digest,
        market_digest: prepared.quote_market_digest,
        slot,
    };
    let public_json = quote_public_json(
        prepared,
        quantity,
        quantity_blinding,
        direction,
        winner_index,
        winner_value,
        slot,
    );
    let quote_context = complete_quote_context(job_id, request_context);
    let evaluation_wires = proof_parties
        .iter_mut()
        .map(|party| {
            party
                .call("quote_evaluations", json!({"job_id": hex::encode(job_id)}))
                .and_then(|value| public_wire(&value, "quote evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let evaluations = evaluation_wires
        .iter()
        .map(|raw| match decode_quote(raw)? {
            QuoteEnvelope {
                job_id: wire_job,
                message: QuoteMessage::Evaluations(value),
            } if wire_job == job_id => Ok(value),
            _ => Err("quote proof party returned another evaluation type".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let circuit = QuoteCircuit::new(32, 32);
    let committee = (1..=proof_parties.len()).collect::<Vec<_>>();
    let statement = quote_statement_from_evaluations(
        &circuit,
        &evaluations,
        &public,
        winner_index,
        winner_value,
        &committee,
        2,
    )?;
    let relation_wires = proof_parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "quote_bind",
                json!({
                    "job_id": hex::encode(job_id),
                    "evaluations": wire_array(&evaluation_wires),
                    "public": public_json.clone(),
                    "quote_context": BASE64.encode(quote_context),
                }),
            )?;
            public_wire(&value, "quote relation evaluation")
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relation_evaluations = relation_wires
        .iter()
        .map(|raw| match decode_quote(raw)? {
            QuoteEnvelope {
                job_id: wire_job,
                message: QuoteMessage::RelationEvaluations(value),
            } if wire_job == job_id => Ok(value),
            _ => Err("quote proof party returned another relation type".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relations = quote_relation_statements_from_evaluations(
        &circuit,
        &statement,
        &public,
        &relation_evaluations,
    )?;
    for party in proof_parties.iter_mut() {
        let value = party.call(
            "quote_relation_bind",
            json!({
                "job_id": hex::encode(job_id),
                "evaluations": wire_array(&relation_wires),
            }),
        )?;
        if value.get("bound").and_then(Value::as_bool) != Some(true) {
            return Err("quote proof party did not bind its relation statement".into());
        }
    }
    let mut seal_wires = Vec::with_capacity(quorum.len());
    let mut round_wires = Vec::with_capacity(quorum.len());
    let mut seals = Vec::with_capacity(quorum.len());
    let mut rounds = Vec::with_capacity(quorum.len());
    for party in &quorum {
        let value = proof_parties[*party - 1]
            .call("quote_round1", json!({"job_id": hex::encode(job_id)}))?;
        let seal_wire = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "quote proof party omitted its round-one seal".to_string())?,
            "quote round-one seal",
        )?;
        let round_wire = public_wire(
            value
                .get("round")
                .ok_or_else(|| "quote proof party omitted round one".to_string())?,
            "quote round one",
        )?;
        seals.push(match decode_quote(&seal_wire)? {
            QuoteEnvelope {
                job_id: wire_job,
                message: QuoteMessage::Round1Seal(value),
            } if wire_job == job_id => value,
            _ => return Err("quote proof party returned another seal type".into()),
        });
        rounds.push(match decode_quote(&round_wire)? {
            QuoteEnvelope {
                job_id: wire_job,
                message: QuoteMessage::Round1(value),
            } if wire_job == job_id => value,
            _ => return Err("quote proof party returned another round-one type".into()),
        });
        seal_wires.push(seal_wire);
        round_wires.push(round_wire);
    }
    let challenge = make_quote_challenges(
        &circuit,
        &statement,
        &relations,
        &public,
        QuoteChallengeTranscript {
            rounds: &rounds,
            seals: &seals,
            quorum: &quorum,
            context: &quote_context,
        },
    )?;
    let challenge = match cross_quote(job_id, QuoteMessage::Challenge(challenge))? {
        QuoteMessage::Challenge(value) => value,
        _ => return Err("quote wire changed the challenge type".into()),
    };
    let challenge_wire = encode_quote(&QuoteEnvelope {
        job_id,
        message: QuoteMessage::Challenge(challenge.clone()),
    })?;
    let mut response_wires = Vec::with_capacity(quorum.len());
    let mut responses = Vec::with_capacity(quorum.len());
    for party in &quorum {
        let value = proof_parties[*party - 1].call(
            "quote_round2",
            json!({
                "job_id": hex::encode(job_id),
                "challenge": BASE64.encode(&challenge_wire),
            }),
        )?;
        let wire = public_wire(&value, "quote round two")?;
        responses.push(match decode_quote(&wire)? {
            QuoteEnvelope {
                job_id: wire_job,
                message: QuoteMessage::Round2(value),
            } if wire_job == job_id => value,
            _ => return Err("quote proof party returned another response type".into()),
        });
        response_wires.push(wire);
    }
    let proof = assemble_quote_from_rounds(
        &circuit,
        &statement,
        &relations,
        &public,
        &rounds,
        &seals,
        &responses,
        &quorum,
        &quote_context,
    )?;
    let bundle = QuoteVerificationBundle {
        context: quote_context,
        eligibility_bits: 32,
        span_bits: 32,
        public,
        proof,
    };
    let digest = bundle.verify()?;
    let expected_digest = hex::encode(digest);
    for party in proof_parties.iter_mut() {
        let value = party.call(
            "quote_finalize",
            json!({
                "job_id": hex::encode(job_id),
                "rounds": wire_array(&round_wires),
                "seals": wire_array(&seal_wires),
                "responses": wire_array(&response_wires),
                "quorum": quorum,
            }),
        )?;
        if value.get("quote_digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
            return Err("proof parties finalized different complete quote proofs".into());
        }
    }
    Ok(bundle)
}

fn run_proof_party(arguments: &[String]) -> Result<(), String> {
    let value = |name: &str| -> Result<&str, String> {
        let position = arguments
            .iter()
            .position(|argument| argument == name)
            .ok_or_else(|| format!("proof-party mode requires {name}"))?;
        arguments
            .get(position + 1)
            .map(String::as_str)
            .ok_or_else(|| format!("{name} requires a value"))
    };
    let node = value("--node")?
        .parse::<u16>()
        .map_err(|_| "--node must be an unsigned 16-bit integer".to_string())?;
    let proof_root = PathBuf::from(value("--proof-root")?);
    let state_file = PathBuf::from(value("--proof-state")?);
    let passphrase_file = PathBuf::from(value("--proof-passphrase-file")?);
    let state_passphrase = node_local_passphrase(&proof_root, &passphrase_file)?;
    let mut party = ProofParty::new(ProofPartyConfig {
        node,
        allowed_root: proof_root,
        state_file,
        state_passphrase,
        n_mm: 4,
        n_parties: 7,
        threshold: 2,
        amount_bits: 16,
        price_bits: 32,
        remainder_bits: 32,
        complete_quote_proof: true,
        quote_eligibility_bits: 34,
        quote_span_bits: 32,
        trusted_defmi_receipt_public: Some(acceptance_defmi_receipt_public()),
        allow_health_signing: true,
    })?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve_proof_party(&mut party, stdin.lock(), stdout.lock())
}

fn distributed_frost_setup(
    parties: &mut [ProofPartyChild],
    session: [u8; 32],
) -> Result<frost::keys::PublicKeyPackage, String> {
    let statuses = parties
        .iter_mut()
        .map(|party| party.call("frost_status", json!({})))
        .collect::<Result<Vec<_>, _>>()?;
    let ready = statuses
        .iter()
        .filter(|status| status.get("ready").and_then(Value::as_bool) == Some(true))
        .count();
    if ready != 0 {
        if ready != parties.len() {
            return Err("FROST durable group is present on only part of the node set".into());
        }
        let expected_session = hex::encode(session);
        if statuses.iter().any(|status| {
            status.get("session").and_then(Value::as_str) != Some(expected_session.as_str())
        }) {
            return Err("FROST durable group belongs to another DKG session".into());
        }
        let encoded = statuses
            .iter()
            .map(|status| {
                BASE64
                    .decode(
                        status
                            .get("public_package")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                "FROST ready node omitted its public package".to_string()
                            })?,
                    )
                    .map_err(|_| "FROST durable public package is malformed".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if encoded.iter().skip(1).any(|value| value != &encoded[0]) {
            return Err("FROST durable nodes disagree on the group public key".into());
        }
        return frost::keys::PublicKeyPackage::deserialize(&encoded[0])
            .map_err(|_| "FROST durable public key cannot be decoded".into());
    }
    let identities = parties
        .iter_mut()
        .map(|party| party.call("frost_identity", json!({"session": hex::encode(session)})))
        .collect::<Result<Vec<_>, _>>()?;
    let entries = Value::Array(identities.clone());
    let confirmations = parties
        .iter_mut()
        .map(|party| {
            party.call(
                "frost_configure_peers",
                json!({
                    "session": hex::encode(session),
                    "entries": entries.clone(),
                }),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifest_digests = confirmations
        .iter()
        .filter_map(|value| value.get("manifest_digest").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if manifest_digests.len() != 1 || confirmations.len() != parties.len() {
        return Err("FROST nodes did not confirm one identical peer manifest".into());
    }
    let confirmation_values = Value::Array(
        confirmations
            .iter()
            .map(|value| {
                json!({
                    "party": value.get("party").cloned().unwrap_or(Value::Null),
                    "confirmation": value.get("confirmation").cloned().unwrap_or(Value::Null),
                })
            })
            .collect(),
    );
    for party in parties.iter_mut() {
        party.call(
            "frost_confirm_peers",
            json!({"confirmations": confirmation_values.clone()}),
        )?;
    }
    let broadcasts = parties
        .iter_mut()
        .map(|party| party.call("frost_dkg_round1", json!({})))
        .collect::<Result<Vec<_>, _>>()?;
    let broadcast_values = Value::Array(broadcasts.clone());
    let directed = parties
        .iter_mut()
        .map(|party| {
            party.call(
                "frost_dkg_round2",
                json!({"broadcasts": broadcast_values.clone()}),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut incoming = (0..parties.len()).map(|_| Vec::new()).collect::<Vec<_>>();
    for sender in directed {
        for envelope in sender
            .get("encrypted")
            .and_then(Value::as_array)
            .ok_or_else(|| "FROST node omitted its encrypted directed packages".to_string())?
        {
            let recipient = envelope
                .get("recipient")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| (1..=parties.len()).contains(value))
                .ok_or_else(|| "FROST directed package has an invalid recipient".to_string())?;
            incoming[recipient - 1].push(envelope.clone());
        }
    }
    let mut encoded_public = Vec::new();
    for (party, incoming) in parties.iter_mut().zip(incoming) {
        let result = party.call(
            "frost_dkg_finalize",
            json!({
                "broadcasts": broadcast_values.clone(),
                "incoming": incoming,
            }),
        )?;
        encoded_public.push(
            BASE64
                .decode(
                    result
                        .get("public_package")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "FROST node omitted the group public key".to_string())?,
                )
                .map_err(|_| "FROST public key package is malformed")?,
        );
    }
    if encoded_public
        .iter()
        .skip(1)
        .any(|package| package != &encoded_public[0])
    {
        return Err("FROST nodes derived different group public keys".into());
    }
    frost::keys::PublicKeyPackage::deserialize(&encoded_public[0])
        .map_err(|_| "FROST group public key cannot be decoded".into())
}

fn frost_signing_job(message: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"QOMM:FROST:SIGNING-JOB:v1")
        .chain_update(message)
        .finalize()
        .into()
}

fn authorize_zkpi_signing(
    parties: &mut [ProofPartyChild],
    selected: &[usize],
    proof_job: [u8; 32],
    partial: &PartialInstruction,
    amount_range: &[u8],
    price_range: &[u8],
) -> Result<(), String> {
    let message = partial.digest();
    let signing_job = frost_signing_job(&message);
    let quote_digest = match partial.quote_binding {
        QuoteBinding::ProofDigest(value) => value,
        QuoteBinding::LegacyPackedKey(_) => {
            return Err("proof nodes refuse legacy clear quote-key signing".into())
        }
    };
    for party in selected {
        parties[*party - 1].call(
            "authorize_zkpi",
            json!({
                "job_id": hex::encode(proof_job),
                "signing_job_id": hex::encode(signing_job),
                "message": BASE64.encode(message),
                "amount_range": BASE64.encode(amount_range),
                "price_range": BASE64.encode(price_range),
                "asset_commitment": hex::encode(partial.asset_commitment.compress().to_bytes()),
                "payer_handle": hex::encode(partial.payer_handle.compress().to_bytes()),
                "payee_handle": hex::encode(partial.payee_handle.compress().to_bytes()),
                "deadline": partial.deadline,
                "nonce": hex::encode(partial.nonce),
                "quote_digest": hex::encode(quote_digest),
            }),
        )?;
    }
    Ok(())
}

fn authorize_health_signing(
    parties: &mut [ProofPartyChild],
    selected: &[usize],
    stage: &str,
    cluster_digest: [u8; 32],
    message: &[u8],
) -> Result<(), String> {
    let signing_job = frost_signing_job(message);
    for party in selected {
        parties[*party - 1].call(
            "authorize_health",
            json!({
                "signing_job_id": hex::encode(signing_job),
                "message": BASE64.encode(message),
                "stage": stage,
                "cluster_digest": hex::encode(cluster_digest),
            }),
        )?;
    }
    Ok(())
}

fn distributed_frost_sign(
    parties: &mut [ProofPartyChild],
    selected: &[usize],
    message: &[u8],
    public: &frost::keys::PublicKeyPackage,
) -> Result<frost::Signature, String> {
    if selected.len() < 3
        || selected
            .iter()
            .any(|party| !(1..=parties.len()).contains(party))
    {
        return Err("FROST signing quorum is outside the configured node set".into());
    }
    let signing_job = frost_signing_job(message);
    let encoded_message = BASE64.encode(message);
    let commitments = selected
        .iter()
        .map(|party| {
            parties[*party - 1].call(
                "frost_commit",
                json!({
                    "job_id": hex::encode(signing_job),
                    "message": encoded_message,
                }),
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
    let commitment_values = Value::Array(commitments.clone());
    let shares = selected
        .iter()
        .map(|party| {
            parties[*party - 1].call(
                "frost_sign",
                json!({
                    "job_id": hex::encode(signing_job),
                    "message": encoded_message,
                    "commitments": commitment_values.clone(),
                }),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let replay = parties[selected[0] - 1].call(
        "frost_sign",
        json!({
            "job_id": hex::encode(signing_job),
            "message": encoded_message,
            "commitments": commitment_values,
        }),
    );
    if replay.is_ok() {
        return Err("FROST node reused a consumed signing nonce".into());
    }
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

struct LiveProofEvidence {
    job_id: [u8; 32],
    lane: usize,
    admission_sequence: u64,
    admission_ticket_id: [u8; 32],
    instruction: Instruction,
    limit_direction: PriceLimitDirection,
    limit_commitment_point: RistrettoPoint,
    limit_threshold_proof: qomm_proofs::threshold_range::ThresholdRangeProof,
    dvp_proofs: qomm_transport::dvp_issuer::DvpProofs,
    securities_remainder_point: RistrettoPoint,
    cash_remainder_point: RistrettoPoint,
    cash_commitment_point: RistrettoPoint,
    securities_delivery_opening: OpeningEnvelope,
    securities_refund_opening: OpeningEnvelope,
    cash_delivery_opening: OpeningEnvelope,
    cash_refund_opening: OpeningEnvelope,
    asset_id: [u8; 32],
    asset_blinding: Scalar,
    instruction_digest: [u8; 32],
    quote_digest: [u8; 32],
    quote_verification: QuoteVerificationBundle,
    securities_reserve: [u8; 32],
    cash_reserve: [u8; 32],
    cash_commitment: [u8; 32],
    limit_commitment: [u8; 32],
    limit_context: [u8; 32],
    price_limit_proof_digest: [u8; 32],
    range_proof_bytes: usize,
}

impl LiveProofEvidence {
    fn into_handoff(self, frost_public: frost::keys::PublicKeyPackage) -> SettlementHandoff {
        SettlementHandoff {
            job_id: self.job_id,
            lane: self.lane,
            admission_sequence: self.admission_sequence,
            admission_ticket_id: self.admission_ticket_id,
            instruction: self.instruction,
            frost_public,
            quote_digest: self.quote_digest,
            quote_verification: self.quote_verification,
            limit_direction: self.limit_direction,
            limit_commitment: self.limit_commitment_point,
            limit_context: self.limit_context,
            price_limit_proof: self.limit_threshold_proof,
            dvp_proofs: self.dvp_proofs,
            cash_commitment: self.cash_commitment_point,
            securities_remainder: self.securities_remainder_point,
            cash_remainder: self.cash_remainder_point,
            securities_reserve: CompressedRistretto(self.securities_reserve)
                .decompress()
                .expect("verified securities reserve commitment"),
            cash_reserve: CompressedRistretto(self.cash_reserve)
                .decompress()
                .expect("verified cash reserve commitment"),
            securities_delivery_opening: self.securities_delivery_opening,
            securities_refund_opening: self.securities_refund_opening,
            cash_delivery_opening: self.cash_delivery_opening,
            cash_refund_opening: self.cash_refund_opening,
            asset_id: self.asset_id,
            asset_blinding: self.asset_blinding,
            execution_context: None,
            typed_authorization: None,
        }
    }
}

fn proof_opening_share(value: &Value) -> Result<EncryptedOpeningShare, String> {
    let decode32 = |name: &str| -> Result<[u8; 32], String> {
        hex::decode(
            value
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("proof party omitted {name}"))?,
        )
        .map_err(|_| format!("proof party {name} is not hexadecimal"))?
        .try_into()
        .map_err(|_| format!("proof party {name} is not 32 bytes"))
    };
    Ok(EncryptedOpeningShare {
        party: value
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|party| usize::try_from(party).ok())
            .ok_or_else(|| "proof party opening identifier is invalid".to_string())?,
        ephemeral: CompressedRistretto(decode32("ephemeral")?)
            .decompress()
            .ok_or_else(|| "proof party opening ephemeral is not canonical".to_string())?,
        masked_value: Option::<Scalar>::from(Scalar::from_canonical_bytes(decode32(
            "masked_value",
        )?))
        .ok_or_else(|| "proof party opening value mask is not canonical".to_string())?,
        masked_blinding: Option::<Scalar>::from(Scalar::from_canonical_bytes(decode32(
            "masked_blinding",
        )?))
        .ok_or_else(|| "proof party opening blinding mask is not canonical".to_string())?,
    })
}

#[allow(clippy::too_many_arguments)]
fn prove_persistence_lane(
    root: &Path,
    prepared: &PreparedMpc,
    proof_parties: &mut [ProofPartyChild],
    frost_public: &frost::keys::PublicKeyPackage,
    slot: u32,
    lane: usize,
    node_batches: &[(u16, [u8; 32])],
    admission_sequence: u64,
    admission_ticket_id: [u8; 32],
    quote_job_seed: [u8; 32],
    quote_quantity: i64,
    quote_quantity_blinding: u64,
    quote_direction: u8,
    limit_direction: PriceLimitDirection,
    limit_commitment: RistrettoPoint,
    limit_context: [u8; 32],
    taker_handle: RistrettoPoint,
    now: u64,
) -> Result<LiveProofEvidence, String> {
    const THRESHOLD: usize = 2;
    const AMOUNT_BITS: usize = 16;
    const PRICE_BITS: usize = 32;
    let quorum = [1_usize, 4, 7];
    let job_id = live_proof_job_id(slot, lane, quote_job_seed)?;
    let persistence_paths = node_batches
        .iter()
        .map(|(node, batch)| {
            root.join("mpc-runs")
                .join(&prepared.source_digest[..16])
                .join(format!("slot-{slot:010}"))
                .join(format!("lane-{lane:04}"))
                .join(hex::encode(batch))
                .join(format!("node-{node}"))
                .join("Persistence")
                .join(format!("Transactions-P{node}.data"))
        })
        .collect::<Vec<_>>();
    if persistence_paths.iter().any(|path| !path.is_file()) {
        return Err(format!(
            "admission lane {lane} lacks one or more node-local MPC proof handoffs"
        ));
    }

    // Each child is an OS process with access only to its configured root and
    // its own `Transactions-Pn.data`. The coordinator never constructs an
    // `MpcZkpiNode`, `MpcDvpNode`, scalar-share map, or proof-round secret.
    if proof_parties.len() != persistence_paths.len() {
        return Err("proof-party population differs from the MPC population".into());
    }
    for (node, (party, path)) in proof_parties
        .iter_mut()
        .zip(persistence_paths.iter())
        .enumerate()
    {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "node persistence escaped the acceptance root")?
            .to_str()
            .ok_or_else(|| "node persistence path is not UTF-8".to_string())?;
        let loaded = party.call(
            "load",
            json!({
                "job_id": hex::encode(job_id),
                "persistence": relative,
                "quote_digest": hex::encode(quote_job_seed),
            }),
        )?;
        if loaded.get("party").and_then(Value::as_u64) != Some(node as u64 + 1) {
            return Err("proof-party loaded another node's persistence".into());
        }
    }

    let quote_verification = prove_complete_quote(
        prepared,
        proof_parties,
        job_id,
        quote_quantity,
        quote_quantity_blinding,
        quote_direction,
        admission_sequence,
        limit_context,
    )?;
    let quote_digest = quote_verification.verify()?;

    let key = Pedersen::new(b"qomm:defmi:v1");
    let bounds = Bounds {
        amount_bits: AMOUNT_BITS,
        price_bits: PRICE_BITS,
        max_horizon: 3_600,
    };
    let maker_handle_evaluations = proof_parties
        .iter_mut()
        .map(|party| {
            party.call(
                "maker_handle_evaluation",
                json!({"job_id": hex::encode(job_id)}),
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    if maker_handle_evaluations.len() != proof_parties.len() {
        return Err("winning Maker handle omitted a proof party".into());
    }
    let mut maker_handle_points = BTreeMap::new();
    for evaluation in &maker_handle_evaluations {
        let party = evaluation
            .get("party")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| "winning Maker handle evaluation has an invalid party".to_string())?;
        let encoded: [u8; 32] = hex::decode(
            evaluation
                .get("point")
                .and_then(Value::as_str)
                .ok_or_else(|| "winning Maker handle evaluation omitted its point".to_string())?,
        )
        .map_err(|_| "winning Maker handle evaluation is not hexadecimal")?
        .try_into()
        .map_err(|_| "winning Maker handle evaluation is not 32 bytes")?;
        let point = CompressedRistretto(encoded).decompress().ok_or_else(|| {
            "winning Maker handle evaluation is not a Ristretto point".to_string()
        })?;
        if !(1..=proof_parties.len()).contains(&party)
            || maker_handle_points.insert(party, point).is_some()
        {
            return Err("winning Maker handle evaluation duplicated a committee party".into());
        }
    }
    let maker_handle = coefficient_commitments_from_evaluations(&maker_handle_points, THRESHOLD)?
        .first()
        .copied()
        .ok_or_else(|| "winning Maker handle coefficient ladder is empty".to_string())?;
    if maker_handle == RistrettoPoint::default() || maker_handle == taker_handle {
        return Err("winning Maker and Taker handles must be distinct non-identity points".into());
    }
    let zkpi_evaluation_wires = proof_parties
        .iter_mut()
        .map(|party| {
            party
                .call("zkpi_evaluations", json!({"job_id": hex::encode(job_id)}))
                .and_then(|value| public_wire(&value, "zkPI evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let zkpi_evaluations = zkpi_evaluation_wires
        .iter()
        .map(
            |raw| match decode_zkpi(raw).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::Evaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("zkPI proof party returned another job or message type".into()),
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let zkpi_statements = zkpi_statements(&zkpi_evaluations, THRESHOLD)?;
    let zkpi_relations = proof_parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "zkpi_bind",
                json!({
                    "job_id": hex::encode(job_id),
                    "evaluations": wire_array(&zkpi_evaluation_wires),
                    "maker_handle_evaluations": maker_handle_evaluations.clone(),
                }),
            )?;
            match decode_zkpi(&public_wire(&value, "zkPI relation")?)
                .map_err(|error| error.to_string())?
            {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::RelationEvaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("zkPI proof party returned another relation type".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let zkpi_relation_statements = zkpi_relation_statements(&zkpi_statements, &zkpi_relations)?;
    let mut zkpi_seals = Vec::new();
    let mut zkpi_round1 = Vec::new();
    for party in quorum {
        let value =
            proof_parties[party - 1].call("zkpi_round1", json!({"job_id": hex::encode(job_id)}))?;
        let seal = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "proof party omitted zkPI round-one seal".to_string())?,
            "zkPI round-one seal",
        )?;
        let round = public_wire(
            value
                .get("round")
                .ok_or_else(|| "proof party omitted zkPI round one".to_string())?,
            "zkPI round one",
        )?;
        zkpi_seals.push(
            match decode_zkpi(&seal).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::Round1Seal(value),
                } if wire_job == job_id => value,
                _ => return Err("zkPI proof party returned another round-one seal".into()),
            },
        );
        zkpi_round1.push(
            match decode_zkpi(&round).map_err(|error| error.to_string())? {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::Round1(value),
                } if wire_job == job_id => value,
                _ => return Err("zkPI proof party returned another round-one message".into()),
            },
        );
    }
    let zkpi_challenge = make_zkpi_challenge(&zkpi_statements, &zkpi_round1, &zkpi_seals, &quorum)?;
    let zkpi_challenge = match cross_zkpi(job_id, ZkpiMessage::Challenge(zkpi_challenge))? {
        ZkpiMessage::Challenge(value) => value,
        _ => return Err("zkPI wire changed the challenge type".into()),
    };
    let zkpi_challenge_wire = encode_zkpi(&ZkpiEnvelope {
        job_id,
        message: ZkpiMessage::Challenge(zkpi_challenge.clone()),
    })
    .map_err(|error| error.to_string())?;
    let zkpi_round2 = quorum
        .iter()
        .map(|party| {
            let value = proof_parties[*party - 1].call(
                "zkpi_round2",
                json!({
                    "job_id": hex::encode(job_id),
                    "challenge": BASE64.encode(&zkpi_challenge_wire),
                }),
            )?;
            match decode_zkpi(&public_wire(&value, "zkPI round two")?)
                .map_err(|error| error.to_string())?
            {
                ZkpiEnvelope {
                    job_id: wire_job,
                    message: ZkpiMessage::Round2(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("zkPI proof party returned another round-two message".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let zkpi_proofs = assemble_ranges(
        &key,
        &zkpi_statements,
        &zkpi_relation_statements,
        &zkpi_round1,
        &zkpi_seals,
        &zkpi_round2,
        &quorum,
    )?;
    let amount_range_wire = encode_threshold_range(&zkpi_proofs.amount)?;
    let price_range_wire = encode_threshold_range(&zkpi_proofs.price)?;
    let asset_id: [u8; 32] = Sha256::digest(b"asset:qomm-live-product-v1").into();
    let asset_blinding = Scalar::random(&mut rand_core::OsRng);
    let asset_commitment = key.commit(&asset_scalar(&asset_id), &asset_blinding);
    let (cash_payer, cash_payee) = match limit_direction {
        PriceLimitDirection::MaximumBuyPrice => (taker_handle, maker_handle),
        PriceLimitDirection::MinimumSellPrice => (maker_handle, taker_handle),
    };
    let partial = build_partial_instruction(
        &key,
        &bounds,
        &zkpi_statements,
        zkpi_proofs,
        asset_commitment,
        cash_payer,
        cash_payee,
        now.saturating_add(3_600),
        job_id,
        quote_digest,
    )?;
    authorize_zkpi_signing(
        proof_parties,
        &quorum,
        job_id,
        &partial,
        &amount_range_wire,
        &price_range_wire,
    )?;
    let signature =
        distributed_frost_sign(proof_parties, &quorum, &partial.digest(), frost_public)?;
    let instruction = partial.sealed(signature);
    let venue = Venue::new(key.clone(), &bounds, frost_public.clone()).require_threshold_ranges();
    venue.verify(&instruction, now).map_err(str::to_string)?;

    // Prove the selected quote lies on the executable side of the Taker's
    // commitment. Every node reads the difference sharing from the same MPC
    // persistence file; neither quote, limit, difference nor blinding is
    // reconstructed by the coordinator.
    let limit_evaluation_wires = proof_parties
        .iter_mut()
        .map(|party| {
            party
                .call("limit_evaluations", json!({"job_id": hex::encode(job_id)}))
                .and_then(|value| public_wire(&value, "hidden-limit evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let limit_evaluations = limit_evaluation_wires
        .iter()
        .map(|raw| match decode_limit(raw)? {
            LimitEnvelope {
                job_id: wire_job,
                message: LimitMessage::Evaluations(value),
            } if wire_job == job_id => Ok(value),
            _ => Err("hidden-limit proof party returned another job or message type".into()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    let limit_statement = limit_statement(&limit_evaluations, THRESHOLD)?;
    let expected_difference = match limit_direction {
        PriceLimitDirection::MaximumBuyPrice => limit_commitment - instruction.price_commitment,
        PriceLimitDirection::MinimumSellPrice => instruction.price_commitment - limit_commitment,
    };
    if limit_statement.commitment.compress() != expected_difference.compress() {
        return Err("MPC hidden-limit witness does not match quote and signed limit".into());
    }
    let limit_relation_evaluations = proof_parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "limit_bind",
                json!({
                    "job_id": hex::encode(job_id),
                    "evaluations": wire_array(&limit_evaluation_wires),
                }),
            )?;
            match decode_limit(&public_wire(&value, "hidden-limit relation")?)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::RelationEvaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("hidden-limit proof party returned another relation type".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let limit_relations = limit_relations(&limit_statement, &limit_relation_evaluations)?;
    let bound_limit_context = price_limit_context(
        limit_direction,
        PRICE_BITS,
        &instruction.price_commitment,
        &limit_commitment,
        &limit_context,
    );
    let mut limit_seals = Vec::new();
    let mut limit_round1 = Vec::new();
    for party in quorum {
        let value = proof_parties[party - 1].call(
            "limit_round1",
            json!({
                "job_id": hex::encode(job_id),
                "context": hex::encode(bound_limit_context),
            }),
        )?;
        limit_seals.push(
            match decode_limit(&public_wire(
                value
                    .get("seal")
                    .ok_or_else(|| "proof party omitted hidden-limit seal".to_string())?,
                "hidden-limit seal",
            )?)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::Round1Seal(value),
                } if wire_job == job_id => value,
                _ => return Err("hidden-limit proof party returned another seal".into()),
            },
        );
        limit_round1.push(
            match decode_limit(&public_wire(
                value
                    .get("round")
                    .ok_or_else(|| "proof party omitted hidden-limit round one".to_string())?,
                "hidden-limit round one",
            )?)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::Round1(value),
                } if wire_job == job_id => value,
                _ => return Err("hidden-limit proof party returned another first round".into()),
            },
        );
    }
    let limit_challenge = make_limit_challenge(
        &limit_statement,
        &limit_round1,
        &limit_seals,
        &quorum,
        &bound_limit_context,
    )?;
    let limit_challenge_wire = encode_limit(&LimitEnvelope {
        job_id,
        message: LimitMessage::Challenge(limit_challenge.clone()),
    })?;
    let limit_round2 = quorum
        .iter()
        .map(|party| {
            let value = proof_parties[*party - 1].call(
                "limit_round2",
                json!({
                    "job_id": hex::encode(job_id),
                    "challenge": BASE64.encode(&limit_challenge_wire),
                }),
            )?;
            match decode_limit(&public_wire(&value, "hidden-limit round two")?)? {
                LimitEnvelope {
                    job_id: wire_job,
                    message: LimitMessage::Round2(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("hidden-limit proof party returned another second round".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let limit_threshold_proof = assemble_limit(
        &key,
        &limit_statement,
        &limit_relations,
        &limit_round1,
        &limit_seals,
        &limit_round2,
        &quorum,
        &bound_limit_context,
    )?;
    let limit_proof = threshold_price_limit(
        &key,
        &instruction.price_commitment,
        &limit_commitment,
        limit_direction,
        PRICE_BITS,
        &limit_context,
        limit_threshold_proof.clone(),
    )?;
    let price_limit_proof_digest = limit_proof.digest(
        &instruction.price_commitment,
        &limit_commitment,
        &limit_context,
    );

    let dvp_evaluation_wires = proof_parties
        .iter_mut()
        .map(|party| {
            party
                .call("dvp_evaluations", json!({"job_id": hex::encode(job_id)}))
                .and_then(|value| public_wire(&value, "DvP evaluation"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let dvp_evaluations = dvp_evaluation_wires
        .iter()
        .map(
            |raw| match decode_dvp(raw).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::Evaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("DvP proof party returned another job or message type".into()),
            },
        )
        .collect::<Result<Vec<_>, String>>()?;
    let constant = |values: BTreeMap<usize, RistrettoPoint>| -> Result<RistrettoPoint, String> {
        coefficient_commitments_from_evaluations(&values, THRESHOLD).and_then(|ladder| {
            ladder
                .first()
                .copied()
                .ok_or_else(|| "empty VSS ladder".into())
        })
    };
    let cash_commitment = constant(
        dvp_evaluations
            .iter()
            .map(|node| (node.party, node.product.relation))
            .collect(),
    )?;
    let securities_remainder = constant(
        dvp_evaluations
            .iter()
            .map(|node| (node.party, node.securities_remainder.value))
            .collect(),
    )?;
    let cash_remainder = constant(
        dvp_evaluations
            .iter()
            .map(|node| (node.party, node.cash_remainder.value))
            .collect(),
    )?;
    let dvp_statements = dvp_statements(
        &instruction.amount_commitment,
        &instruction.price_commitment,
        &cash_commitment,
        &securities_remainder,
        &cash_remainder,
        &dvp_evaluations,
        THRESHOLD,
    )?;
    let dvp_relations = proof_parties
        .iter_mut()
        .map(|party| {
            let value = party.call(
                "dvp_bind",
                json!({
                    "job_id": hex::encode(job_id),
                    "evaluations": wire_array(&dvp_evaluation_wires),
                }),
            )?;
            match decode_dvp(&public_wire(&value, "DvP relation")?)
                .map_err(|error| error.to_string())?
            {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::RelationEvaluations(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("DvP proof party returned another relation type".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let dvp_relation_statements = dvp_relation_statements(&dvp_statements, &dvp_relations)?;
    let mut dvp_seals = Vec::new();
    let mut dvp_round1 = Vec::new();
    for party in quorum {
        let value =
            proof_parties[party - 1].call("dvp_round1", json!({"job_id": hex::encode(job_id)}))?;
        let seal = public_wire(
            value
                .get("seal")
                .ok_or_else(|| "proof party omitted DvP round-one seal".to_string())?,
            "DvP round-one seal",
        )?;
        let round = public_wire(
            value
                .get("round")
                .ok_or_else(|| "proof party omitted DvP round one".to_string())?,
            "DvP round one",
        )?;
        dvp_seals.push(
            match decode_dvp(&seal).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::Round1Seal(value),
                } if wire_job == job_id => value,
                _ => return Err("DvP proof party returned another round-one seal".into()),
            },
        );
        dvp_round1.push(
            match decode_dvp(&round).map_err(|error| error.to_string())? {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::Round1(value),
                } if wire_job == job_id => value,
                _ => return Err("DvP proof party returned another round-one message".into()),
            },
        );
    }
    let dvp_challenge = make_dvp_challenge(&dvp_statements, &dvp_round1, &dvp_seals, &quorum)?;
    let dvp_challenge = match cross_dvp(job_id, DvpMessage::Challenge(dvp_challenge))? {
        DvpMessage::Challenge(value) => value,
        _ => return Err("DvP wire changed the challenge type".into()),
    };
    let dvp_challenge_wire = encode_dvp(&DvpEnvelope {
        job_id,
        message: DvpMessage::Challenge(dvp_challenge.clone()),
    })
    .map_err(|error| error.to_string())?;
    let dvp_round2 = quorum
        .iter()
        .map(|party| {
            let value = proof_parties[*party - 1].call(
                "dvp_round2",
                json!({
                    "job_id": hex::encode(job_id),
                    "challenge": BASE64.encode(&dvp_challenge_wire),
                }),
            )?;
            match decode_dvp(&public_wire(&value, "DvP round two")?)
                .map_err(|error| error.to_string())?
            {
                DvpEnvelope {
                    job_id: wire_job,
                    message: DvpMessage::Round2(value),
                } if wire_job == job_id => Ok(value),
                _ => Err("DvP proof party returned another round-two message".into()),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let dvp_proofs = assemble_dvp_proofs(
        &key,
        &dvp_statements,
        &dvp_relation_statements,
        &dvp_round1,
        &dvp_seals,
        &dvp_round2,
        &quorum,
    )?;
    if !verify_product(
        &key,
        &mut Transcript::new(DVP_PRODUCT_CONTEXT),
        &instruction.amount_commitment,
        &instruction.price_commitment,
        &cash_commitment,
        &dvp_proofs.product,
    ) || !verify_threshold_range(
        &key,
        &securities_remainder,
        &dvp_proofs.securities_remainder,
        DVP_SECURITIES_REMAINDER_CONTEXT,
    ) || !verify_threshold_range(
        &key,
        &cash_remainder,
        &dvp_proofs.cash_remainder,
        DVP_CASH_REMAINDER_CONTEXT,
    ) {
        return Err("public DvP verifier rejected the node-local MPC handoff".into());
    }
    let collect_opening = |leg: &str,
                           recipient: RistrettoPoint,
                           proof_parties: &mut [ProofPartyChild]|
     -> Result<OpeningEnvelope, String> {
        let context = opening_context(&job_id, leg)?;
        let recipient_wire = hex::encode(recipient.compress().to_bytes());
        let context_wire = hex::encode(context);
        let shares = quorum
            .iter()
            .map(|party_id| {
                let party = &mut proof_parties[*party_id - 1];
                let value = party.call(
                    "claim_opening_share",
                    json!({
                        "job_id": hex::encode(job_id),
                        "leg": leg,
                        "recipient_view": recipient_wire.clone(),
                    }),
                )?;
                if value.get("context").and_then(Value::as_str) != Some(context_wire.as_str())
                    || value.get("recipient_view").and_then(Value::as_str)
                        != Some(recipient_wire.as_str())
                {
                    return Err(
                        "proof party changed a claim-opening context or recipient".to_string()
                    );
                }
                proof_opening_share(&value)
            })
            .collect::<Result<Vec<_>, String>>()?;
        OpeningEnvelope::new(context, THRESHOLD + 1, recipient, shares)
    };
    // Cash payer is the securities buyer. Cash payee is the securities seller,
    // so these recipient assignments do not depend on buy/sell direction.
    let securities_delivery_opening = collect_opening(
        "securities_delivery",
        instruction.payer_handle,
        proof_parties,
    )?;
    let securities_refund_opening =
        collect_opening("securities_refund", instruction.payee_handle, proof_parties)?;
    let cash_delivery_opening =
        collect_opening("cash_delivery", instruction.payee_handle, proof_parties)?;
    let cash_refund_opening =
        collect_opening("cash_refund", instruction.payer_handle, proof_parties)?;
    for party in proof_parties.iter_mut() {
        party.call("complete", json!({"job_id": hex::encode(job_id)}))?;
    }
    let instruction_digest = Sha256::digest(qomm_zkpi::wire::encode(&instruction)).into();
    Ok(LiveProofEvidence {
        job_id,
        lane,
        admission_sequence,
        admission_ticket_id,
        instruction: instruction.clone(),
        limit_direction,
        limit_commitment_point: limit_commitment,
        limit_threshold_proof,
        dvp_proofs: dvp_proofs.clone(),
        securities_remainder_point: securities_remainder,
        cash_remainder_point: cash_remainder,
        cash_commitment_point: cash_commitment,
        securities_delivery_opening,
        securities_refund_opening,
        cash_delivery_opening,
        cash_refund_opening,
        asset_id,
        asset_blinding,
        instruction_digest,
        quote_digest,
        quote_verification,
        securities_reserve: (instruction.amount_commitment + securities_remainder)
            .compress()
            .to_bytes(),
        cash_reserve: (cash_commitment + cash_remainder).compress().to_bytes(),
        cash_commitment: cash_commitment.compress().to_bytes(),
        limit_commitment: limit_commitment.compress().to_bytes(),
        limit_context,
        price_limit_proof_digest,
        range_proof_bytes: instruction.range_proof_bytes_len(),
    })
}

#[allow(clippy::too_many_arguments)]
fn start_node(
    node: u16,
    bundle: &Bundle,
    store: Arc<NodeStore>,
    coordinator_fingerprint: &str,
    client_identities: &[ClientIdentity],
    kyb_policy: Arc<KybPolicy>,
    sealing_keys: NodeSealingKeys,
    registry: Arc<ProgramRegistry>,
    delay_ms: u64,
) -> Result<(ResidentNodeServer, Transport), String> {
    let mut principals = BTreeMap::new();
    for identity in client_identities {
        principals.insert(
            identity.fingerprint.clone(),
            Principal::client(
                identity.frame_key.clone(),
                &identity.scope_nullifier,
                identity.presentation.clone(),
            )?,
        );
    }
    principals.insert(
        coordinator_fingerprint.to_string(),
        Principal::coordinator(),
    );
    let mut server = ResidentNodeServer::new(
        node,
        "127.0.0.1",
        0,
        server_ssl_context(&bundle.cert, &bundle.key, &bundle.ca)?,
        principals,
        Some(kyb_policy),
        sealing_keys,
        store,
        Some(registry),
        RateLimitPolicy::default(),
        Duration::from_secs(30),
        Duration::from_millis(delay_ms),
    )?;
    let transport = match server.start() {
        Ok(_) => Transport::Tcp,
        Err(error) if error.contains("Operation not permitted") => Transport::Local,
        Err(error) => return Err(error),
    };
    Ok((server, transport))
}

fn client_for(
    bundle: &Bundle,
    server: &ResidentNodeServer,
    transport: Transport,
) -> Result<ClusterClient, String> {
    let tls = client_ssl_context(&bundle.cert, &bundle.key, &bundle.ca)?;
    let server_name = format!("node-{}", server.node);
    Ok(match transport {
        Transport::Tcp => ClusterClient::Tcp(ResidentNodeClient::new(
            "127.0.0.1",
            server.port,
            tls,
            server_name,
            3,
        )),
        Transport::Local => ClusterClient::Local(server.local_client(tls, server_name, 3)),
    })
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn wait_for_pretrade_ack(
    path: &Path,
    timeout: Duration,
) -> Result<qomm_transport::pretrade_authority::PretradeAcknowledgement, String> {
    let started = Instant::now();
    loop {
        if path.exists() {
            return read_ack_private(path);
        }
        if started.elapsed() >= timeout {
            return Err(format!(
                "timed out waiting for DeFMI pre-trade acknowledgement: {}",
                path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct AcceptanceConfig<'a> {
    slots: u32,
    pretrade_ack_timeout: Duration,
    mp_spdz_root: &'a Path,
    runner: &'a Path,
    evidence_out: Option<&'a Path>,
    pretrade_authority_out: &'a Path,
    pretrade_ack_in: &'a Path,
    external_kyb_trust_anchor: &'a Path,
    external_kyb_bundle: &'a Path,
}

fn run(config: AcceptanceConfig<'_>) -> Result<bool, String> {
    let AcceptanceConfig {
        slots,
        pretrade_ack_timeout,
        mp_spdz_root,
        runner,
        evidence_out,
        pretrade_authority_out,
        pretrade_ack_in,
        external_kyb_trust_anchor,
        external_kyb_bundle,
    } = config;
    if slots < 2 {
        return Err("at least two slots are required".into());
    }
    let root = std::env::temp_dir().join(format!(
        "qomm-seven-node-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    eprintln!("acceptance root: {}", root.display());
    let _root_guard = TempRoot(root.clone());
    let prepared = prepare_real_mpc(&root, mp_spdz_root, runner)?;
    let (ca_key, ca_cert) = create_ca("QOMM seven-node acceptance CA", 3650)?;
    let client_bundles = (0..N_CLIENTS)
        .map(|client| issue(&root, &format!("client-{client}"), &ca_key, &ca_cert))
        .collect::<Result<Vec<_>, _>>()?;
    let coordinator_bundle = issue(&root, "coordinator", &ca_key, &ca_cert)?;
    let node_bundles = (0..7)
        .map(|node| issue(&root, &format!("node-{node}"), &ca_key, &ca_cert))
        .collect::<Result<Vec<_>, _>>()?;
    let coordinator_fingerprint = certificate_fingerprint(&coordinator_bundle.der);
    let venue_scope = b"qomm-seven-node/venue/orders";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let external_anchor = read_external_kyb_trust_anchor(external_kyb_trust_anchor)?;
    let external_bundle = read_external_kyb_bundle(external_kyb_bundle)?;
    if external_bundle.provider != external_anchor.provider
        || external_bundle.audience != external_anchor.audience
    {
        return Err("external KYB bundle does not match the pinned trust anchor".into());
    }
    let required_external_labels = BTreeSet::from([
        "taker-sell".to_string(),
        "taker-shared-buy".to_string(),
        "taker-cover".to_string(),
        "maker-0".to_string(),
        "maker-1".to_string(),
        "maker-2".to_string(),
        "maker-3".to_string(),
    ]);
    if external_bundle
        .assertions
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != required_external_labels
    {
        return Err("external KYB bundle does not cover the closed participant population".into());
    }
    let verified_external = external_bundle
        .assertions
        .iter()
        .map(|(label, assertion)| {
            external_anchor
                .verify(assertion, now)
                .map(|verified| (label.clone(), verified))
                .map_err(|error| format!("external KYB assertion {label} failed: {error}"))
        })
        .collect::<Result<BTreeMap<String, VerifiedExternalKyb>, String>>()?;
    let external_kyb_evidence_digest = external_bundle.evidence_digest()?;
    let kyb_seed: [u8; 32] = Sha256::digest(b"QOMM:ACCEPTANCE:KYB-ISSUER-KEY:v1").into();
    let mut issuer = KybIssuer::with_signing_key(5, SigningKey::from_bytes(&kyb_seed))
        .map_err(str::to_string)?;
    let enroll_external = |issuer: &mut KybIssuer, label: &str| -> Result<KybCredential, String> {
        let verified = verified_external
            .get(label)
            .ok_or_else(|| format!("missing verified external KYB assertion {label}"))?;
        issuer
            .enroll(
                &verified.control_group_id,
                verified.attributes.clone(),
                &mut rand_core::OsRng,
            )
            .map_err(str::to_string)
    };
    // Clients 1 and 2 deliberately use different TLS identities/wallet
    // handles backed by the same legal-entity credential. Their simultaneous
    // buy RFQs therefore compete for one entity-level DeFMI facility.
    let shared_entity = enroll_external(&mut issuer, "taker-shared-buy")?;
    let mut credentials: Vec<KybCredential> = Vec::with_capacity(N_CLIENTS);
    credentials.push(enroll_external(&mut issuer, "taker-sell")?);
    credentials.push(shared_entity.clone());
    credentials.push(shared_entity);
    credentials.push(enroll_external(&mut issuer, "taker-cover")?);
    let maker_credentials = (0..4)
        .map(|maker| enroll_external(&mut issuer, &format!("maker-{maker}")))
        .collect::<Result<Vec<_>, _>>()?;
    let cohort = cohort_id("JP", "bank", 2);
    let node_key_stores = (0..7)
        .map(|node| NodeKeyStore::create(&root, node, now))
        .collect::<Result<Vec<_>, _>>()?;
    let node_public_keys = node_key_stores
        .iter()
        .map(|store| {
            store
                .load(now)
                .map(|keys| keys.public_keys().map(|key| key.to_bytes()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let kyb_registry = issuer
        .publish(&cohort, 1, now + 3_600)
        .map_err(str::to_string)?;
    let client_identities = client_bundles
        .into_iter()
        .zip(credentials)
        .enumerate()
        .map(|(client, (bundle, credential))| {
            let fingerprint = certificate_fingerprint(&bundle.der);
            let presentation = present(
                &credential,
                &kyb_registry,
                venue_scope,
                fingerprint.as_bytes(),
                &mut rand_core::OsRng,
            )
            .map_err(str::to_string)?;
            let frame_key = Sha256::new()
                .chain_update(b"qomm-seven-node-frame-key-v1")
                .chain_update((client as u64).to_be_bytes())
                .finalize()
                .to_vec();
            Ok(ClientIdentity {
                bundle,
                fingerprint,
                frame_key,
                scope_nullifier: credential.scope_nullifier(venue_scope),
                presentation,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let commitment_key = Pedersen::new(b"qomm:defmi:v1");
    let venue_id: [u8; 32] = Sha256::digest(b"venue:qomm-live-v1").into();
    let defmi_id: [u8; 32] = Sha256::digest(b"defmi:qomm-live-v1").into();
    let traded_asset_id: [u8; 32] = Sha256::digest(b"asset:qomm-live-product-v1").into();
    let cash_asset_id: [u8; 32] = Sha256::digest(b"asset:qomm-live-cash-v1").into();
    let final_slot = slots - 1;
    let maker_identity_contexts = (0..maker_credentials.len())
        .map(|maker| {
            [
                b"QOMM:LIVE:MAKER-IDENTITY-CONTEXT:v1".as_slice(),
                &(maker as u64).to_be_bytes(),
            ]
            .concat()
        })
        .collect::<Vec<_>>();
    let maker_presentations = maker_credentials
        .iter()
        .zip(&maker_identity_contexts)
        .map(|(credential, context)| {
            present(
                credential,
                &kyb_registry,
                venue_scope,
                context,
                &mut rand_core::OsRng,
            )
            .map_err(str::to_string)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut maker_authorities = Vec::with_capacity(maker_credentials.len() * 2);
    for maker in 0..maker_credentials.len() {
        for direction in [Direction::TakerBuys, Direction::TakerSells] {
            let seed: [u8; 32] = Sha256::new()
                .chain_update(b"QOMM:LIVE:MAKER-SIGNING-KEY:v1")
                .chain_update((maker as u64).to_be_bytes())
                .chain_update([direction as u8])
                .finalize()
                .into();
            let signing_key = SigningKey::from_bytes(&seed);
            let (asset_id, opening) = match direction {
                Direction::TakerBuys => (traded_asset_id, MAKER_SECURITIES[maker]),
                Direction::TakerSells => (cash_asset_id, MAKER_CASH[maker]),
            };
            let policy_digest = registered_policy_digest(
                maker,
                prepared
                    .quote_registry
                    .get(maker)
                    .ok_or_else(|| "Maker has no registered price policy".to_string())?,
            );
            let mandate = MakerPolicyMandate {
                venue_id,
                defmi_id,
                policy_digest,
                policy_version: 1,
                asset_id,
                direction,
                reserve_id: Sha256::new()
                    .chain_update(b"QOMM:LIVE:MAKER-RESERVE:v1")
                    .chain_update((maker as u64).to_be_bytes())
                    .chain_update([direction as u8])
                    .finalize()
                    .into(),
                maximum_amount_commitment: commitment_key
                    .commit(&Scalar::from(opening.0), &Scalar::from(opening.1))
                    .compress()
                    .to_bytes(),
                maker_handle: RistrettoPoint::mul_base(&Scalar::from(21_u64 + maker as u64))
                    .compress()
                    .to_bytes(),
                entity_commitment: maker_presentations[maker].entity_commitment(),
                kyb_presentation_digest: maker_presentations[maker].digest(),
                valid_from: now.saturating_sub(1).max(1),
                valid_until: now.saturating_add(3_600),
                auto_execute: true,
                maker_public: signing_key.verifying_key().to_bytes(),
                signature: Signature::from_bytes(&[0_u8; 64]),
            }
            .sign(&signing_key)?;
            mandate.verify(
                &maker_presentations[maker],
                &kyb_registry,
                &issuer.public_key(),
                venue_scope,
                &maker_identity_contexts[maker],
                &cohort,
                now,
            )?;
            maker_authorities.push(MakerPretradeAuthority {
                maker_index: maker as u16,
                mandate,
                identity_context: maker_identity_contexts[maker].clone(),
                presentation: maker_presentations[maker].clone(),
                acceptance_opening: AcceptanceOpening {
                    amount: opening.0,
                    blinding: Scalar::from(opening.1),
                },
            });
        }
    }
    let taker_mandates = (0..3)
        .map(|client| {
            let seed: [u8; 32] = Sha256::new()
                .chain_update(b"QOMM:LIVE:TAKER-SIGNING-KEY:v1")
                .chain_update((client as u64).to_be_bytes())
                .finalize()
                .into();
            let signing_key = SigningKey::from_bytes(&seed);
            let quantity = 10 + 5 * client as u64;
            let quantity_blinding = 151 + client as u64;
            let limit = if client == 0 { 0_u64 } else { 1_000_000_u64 };
            let direction = if client == 0 {
                Direction::TakerSells
            } else {
                Direction::TakerBuys
            };
            let maximum_amount_commitment = if client == 0 {
                commitment_key.commit(
                    &Scalar::from(TAKER_SECURITIES.0),
                    &Scalar::from(TAKER_SECURITIES.1),
                )
            } else {
                commitment_key.commit(&Scalar::from(TAKER_CASH.0), &Scalar::from(TAKER_CASH.1))
            };
            let mandate = TakerExecutionMandate {
                venue_id,
                defmi_id,
                rfq_nullifier: Sha256::new()
                    .chain_update(b"QOMM:LIVE:RFQ-NULLIFIER:v1")
                    .chain_update((client as u64).to_be_bytes())
                    .finalize()
                    .into(),
                asset_id: traded_asset_id,
                reserve_asset_id: match direction {
                    Direction::TakerBuys => cash_asset_id,
                    Direction::TakerSells => traded_asset_id,
                },
                direction,
                quantity_commitment: commitment_key
                    .commit(&Scalar::from(quantity), &Scalar::from(quantity_blinding))
                    .compress()
                    .to_bytes(),
                limit_price_commitment: commitment_key
                    .commit(&Scalar::from(limit), &Scalar::from(101_u64 + client as u64))
                    .compress()
                    .to_bytes(),
                maximum_fee_commitment: commitment_key
                    .commit(
                        &Scalar::from(10_000_u64),
                        &Scalar::from(181_u64 + client as u64),
                    )
                    .compress()
                    .to_bytes(),
                maximum_amount_commitment: maximum_amount_commitment.compress().to_bytes(),
                reserve_id: Sha256::new()
                    .chain_update(b"QOMM:LIVE:TAKER-RESERVE:v1")
                    .chain_update((client as u64).to_be_bytes())
                    .finalize()
                    .into(),
                taker_handle: RistrettoPoint::mul_base(&Scalar::from(101_u64 + client as u64))
                    .compress()
                    .to_bytes(),
                entity_commitment: client_identities[client].presentation.entity_commitment(),
                kyb_presentation_digest: client_identities[client].presentation.digest(),
                admission_ticket_id: principal_ticket_id(
                    final_slot,
                    &client_identities[client].fingerprint,
                )?,
                admission_slot: u64::from(final_slot),
                deadline: now.saturating_add(3_600),
                allow_partial: false,
                auto_settle: true,
                taker_public: signing_key.verifying_key().to_bytes(),
                signature: Signature::from_bytes(&[0_u8; 64]),
            }
            .sign(&signing_key)?;
            mandate.verify(
                &client_identities[client].presentation,
                &kyb_registry,
                &issuer.public_key(),
                venue_scope,
                client_identities[client].fingerprint.as_bytes(),
                &cohort,
                now,
            )?;
            Ok(mandate)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let taker_authorities = taker_mandates
        .iter()
        .enumerate()
        .map(|(client, mandate)| TakerPretradeAuthority {
            client_index: client as u16,
            mandate: mandate.clone(),
            identity_context: client_identities[client].fingerprint.as_bytes().to_vec(),
            presentation: client_identities[client].presentation.clone(),
            acceptance_opening: AcceptanceOpening {
                amount: if client == 0 {
                    TAKER_SECURITIES.0
                } else {
                    TAKER_CASH.0
                },
                blinding: Scalar::from(if client == 0 {
                    TAKER_SECURITIES.1
                } else {
                    TAKER_CASH.1
                }),
            },
        })
        .collect::<Vec<_>>();
    let kyb_policy = Arc::new(KybPolicy::new(
        venue_scope.to_vec(),
        cohort.clone(),
        kyb_registry.clone(),
        issuer.public_key(),
    )?);
    let delays = [8_u64, 13, 21, 34, 55, 70, 85];
    let mut stores = (0..7)
        .map(|node| NodeStore::open(root.join(format!("node-{node}.sqlite3"))).map(Arc::new))
        .collect::<Result<Vec<_>, _>>()?;
    let started = (0..7)
        .map(|node| {
            start_node(
                node as u16,
                &node_bundles[node],
                Arc::clone(&stores[node]),
                &coordinator_fingerprint,
                &client_identities,
                Arc::clone(&kyb_policy),
                node_key_stores[node].load(now)?,
                Arc::clone(&prepared.registries[node]),
                delays[node],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (mut servers, mut transports): (Vec<_>, Vec<_>) = started.into_iter().unzip();
    let mut clients = client_identities
        .iter()
        .map(|identity| {
            servers
                .iter()
                .zip(transports.iter().copied())
                .map(|(server, transport)| client_for(&identity.bundle, server, transport))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut sizes = Vec::new();
    let admission_claims = (0..slots)
        .map(|slot| {
            (0..N_CLIENTS)
                .map(|client| {
                    if slot + 1 == slots && client < taker_mandates.len() {
                        taker_mandates[client]
                            .digest()
                            .expect("pre-verified Taker mandate")
                    } else {
                        Sha256::new()
                            .chain_update(b"QOMM:LIVE:COVER-ADMISSION-CLAIM:v1")
                            .chain_update(slot.to_be_bytes())
                            .chain_update((client as u64).to_be_bytes())
                            .chain_update(client_identities[client].presentation.digest())
                            .finalize()
                            .into()
                    }
                })
                .collect::<Vec<[u8; 32]>>()
        })
        .collect::<Vec<_>>();
    let mut last_requests = vec![vec![Value::Null; 7]; N_CLIENTS];
    let mut last_responses = vec![vec![Value::Null; 7]; N_CLIENTS];
    for slot in 0..slots {
        let payloads = (0..N_CLIENTS)
            .map(|client| {
                let real = slot + 1 == slots && client < taker_mandates.len();
                let input = if real {
                    let mandate = &taker_mandates[client];
                    let (reserve_amount, reserve_blinding) = match mandate.direction {
                        Direction::TakerBuys => TAKER_CASH,
                        Direction::TakerSells => TAKER_SECURITIES,
                    };
                    ResidentRfqInput::from_signed_mandate(
                        mandate,
                        &ResidentRfqCatalogBinding {
                            asset_index: 0,
                            asset_count: 1,
                            traded_asset_id,
                            cash_asset_id,
                            entity_slot: 42,
                        },
                        &ResidentRfqOpenings {
                            quantity: 10 + 5 * client as u64,
                            quantity_blinding: Scalar::from(151 + client as u64),
                            executable_limit: if mandate.direction == Direction::TakerBuys {
                                1_000_000
                            } else {
                                0
                            },
                            limit_blinding: Scalar::from(101 + client as u64),
                            reserve_amount,
                            reserve_blinding: Scalar::from(reserve_blinding),
                            response_mask: Scalar::from(1_000_000_u64),
                            fill_mask: Scalar::from(91 + client as u64),
                        },
                        slot,
                        now,
                    )?
                } else {
                    ResidentRfqInput::cover(&mut rand_core::OsRng)
                };
                input
                    .share(7)
                    .map(|payloads| (real, payloads))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        for node in 0..7 {
            // Deliberately vary arrival order at every node and slot.  The
            // resulting order must still be committee-wide and content-free.
            for offset in 0..N_CLIENTS {
                let client = (offset + node + slot as usize) % N_CLIENTS;
                let (real, shared) = &payloads[client];
                let frame = Frame::new(
                    slot,
                    node,
                    shared[node],
                    &client_identities[client].frame_key,
                )
                .map_err(|error| error.to_string())?;
                let raw = frame.encode();
                sizes.push((*real, raw.len()));
                let request = json!({
                    "version": 1,
                    "request_id": format!("slot-{slot}-node-{node}-client-{client}"),
                    "operation": "submit",
                    "slot": slot,
                    "frame": BASE64.encode(raw),
                    "admission_claim_digest": hex::encode(admission_claims[slot as usize][client]),
                });
                let response = clients[client][node].call(&request)?;
                if response.get("ok").and_then(Value::as_bool) != Some(true) {
                    return Err(format!(
                        "node {node} refused client {client} in slot {slot}: {response}"
                    ));
                }
                last_requests[client][node] = request;
                last_responses[client][node] = response;
            }
        }
    }

    let node = 3_usize;
    for client in &mut clients {
        client[node].close();
    }
    servers[node].stop();
    let frames_before = stores[node].frame_count()?;
    let requests_before = stores[node].request_count()?;
    // Drop every object that owns the original SQLite handle.  Recovery below
    // therefore comes from reopening the on-disk database, rather than from a
    // live Arc that happened to survive the listener restart.
    drop(servers.remove(node));
    transports.remove(node);
    drop(stores.remove(node));
    let reopened_store = Arc::new(NodeStore::open(root.join(format!("node-{node}.sqlite3")))?);
    let reloaded_keys = node_key_stores[node].load(now)?;
    let sealing_key_recovery_works =
        reloaded_keys.public_keys().map(|key| key.to_bytes()) == node_public_keys[node];
    let (restarted, transport) = start_node(
        node as u16,
        &node_bundles[node],
        Arc::clone(&reopened_store),
        &coordinator_fingerprint,
        &client_identities,
        Arc::clone(&kyb_policy),
        reloaded_keys,
        Arc::clone(&prepared.registries[node]),
        delays[node],
    )?;
    servers.insert(node, restarted);
    transports.insert(node, transport);
    stores.insert(node, reopened_store);
    for (client, identity) in client_identities.iter().enumerate() {
        clients[client][node] = client_for(&identity.bundle, &servers[node], transports[node])?;
    }
    let recovered = clients[0][node].call(&last_requests[0][node])?;
    let recovery_works = recovered == last_responses[0][node]
        && stores[node].frame_count()? == frames_before
        && stores[node].request_count()? == requests_before;

    let mut changed = last_requests[0][node].clone();
    let mut payload = [0_u8; qomm_transport::wire::PAYLOAD_BYTES];
    payload[0] = 0x5a;
    let replacement = Frame::new(slots - 1, node, payload, &client_identities[0].frame_key)
        .map_err(|error| error.to_string())?;
    changed["frame"] = Value::String(BASE64.encode(replacement.encode()));
    let changed_reply = clients[0][node].call(&changed)?;
    let different_body_refused = changed_reply.get("ok").and_then(Value::as_bool) == Some(false)
        && changed_reply
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("reused"));

    let slot_counts = (0..slots)
        .map(|slot| {
            stores
                .iter()
                .map(|store| store.frames_for_slot(slot).map(|frames| frames.len()))
                .sum::<Result<usize, String>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_frames_per_slot = 7 * N_CLIENTS;
    let frames_constant = slot_counts
        .iter()
        .all(|count| *count == expected_frames_per_slot);
    let cover_real_same_size = sizes.iter().all(|(_, size)| *size == FRAME_BYTES)
        && sizes.iter().any(|(real, _)| *real)
        && sizes.iter().any(|(real, _)| !*real);

    let shape_digest = prepared.shape_digest.clone();
    let mut coordinators = servers
        .iter()
        .zip(transports.iter().copied())
        .map(|(server, transport)| client_for(&coordinator_bundle, server, transport))
        .collect::<Result<Vec<_>, _>>()?;
    let mut order_digests = Vec::with_capacity(coordinators.len());
    let mut admission_sequences = (0..N_CLIENTS)
        .map(|_| Vec::with_capacity(coordinators.len()))
        .collect::<Vec<_>>();
    let mut admission_tickets = (0..N_CLIENTS)
        .map(|_| Vec::with_capacity(coordinators.len()))
        .collect::<Vec<_>>();
    let mut admission_attestations = (0..N_CLIENTS)
        .map(|_| Vec::with_capacity(coordinators.len()))
        .collect::<Vec<_>>();
    let mut node_batches = Vec::with_capacity(coordinators.len());
    let admitted_principals = client_identities
        .iter()
        .map(|identity| admission_principal_digest(&identity.fingerprint))
        .collect::<Result<Vec<_>, _>>()?;
    for (node, coordinator) in coordinators.iter_mut().enumerate() {
        let closed = coordinator.call(&json!({
            "version": 1,
            "request_id": "close-final",
            "operation": "close_slot",
            "slot": slots - 1,
        }))?;
        if closed.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(format!("node {node} slot close failed: {closed}"));
        }
        order_digests.push(
            closed
                .get("order_digest")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("node {node} omitted its sealed order digest"))?
                .to_string(),
        );
        let mut batch_for_node = None;
        for (client, principal) in admitted_principals.iter().enumerate() {
            let position = coordinator.call(&json!({
                "version": 1,
                "request_id": format!("admission-final-client-{client}"),
                "operation": "admission_position",
                "slot": slots - 1,
                "principal_digest": hex::encode(principal),
            }))?;
            if position.get("ok").and_then(Value::as_bool) != Some(true) {
                return Err(format!(
                    "node {node} admission lookup for client {client} failed: {position}"
                ));
            }
            admission_sequences[client].push(
                position
                    .get("sequence")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("node {node} omitted admission sequence"))?,
            );
            let ticket: [u8; 32] = hex::decode(
                position
                    .get("ticket_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("node {node} omitted admission ticket"))?,
            )
            .map_err(|_| format!("node {node} returned malformed admission ticket"))?
            .try_into()
            .map_err(|_| format!("node {node} returned malformed admission ticket"))?;
            admission_tickets[client].push(ticket);
            let batch: [u8; 32] = hex::decode(
                position
                    .get("batch_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("node {node} omitted batch digest"))?,
            )
            .map_err(|_| format!("node {node} returned malformed batch digest"))?
            .try_into()
            .map_err(|_| format!("node {node} returned malformed batch digest"))?;
            if batch_for_node
                .replace(batch)
                .is_some_and(|prior| prior != batch)
            {
                return Err(format!(
                    "node {node} returned different batches by participant"
                ));
            }
            let claim_digest: [u8; 32] = hex::decode(
                position
                    .get("admission_claim_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("node {node} omitted admission claim"))?,
            )
            .map_err(|_| format!("node {node} returned malformed admission claim"))?
            .try_into()
            .map_err(|_| format!("node {node} returned malformed admission claim"))?;
            let signature: [u8; 64] = hex::decode(
                position
                    .get("node_attestation")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("node {node} omitted admission attestation"))?,
            )
            .map_err(|_| format!("node {node} returned malformed admission attestation"))?
            .try_into()
            .map_err(|_| format!("node {node} returned malformed admission attestation"))?;
            admission_attestations[client].push(NodeAdmissionAttestation {
                node: node as u16,
                slot: u64::from(slots - 1),
                sequence: admission_sequences[client][node],
                principal_digest: *principal,
                ticket_id: ticket,
                claim_digest,
                batch_digest: batch,
                order_digest: hex::decode(
                    position
                        .get("order_digest")
                        .and_then(Value::as_str)
                        .ok_or_else(|| format!("node {node} omitted admission order"))?,
                )
                .map_err(|_| format!("node {node} returned malformed admission order"))?
                .try_into()
                .map_err(|_| format!("node {node} returned malformed admission order"))?,
                signature: Signature::from_bytes(&signature),
            });
        }
        node_batches.push((
            node as u16,
            batch_for_node.ok_or_else(|| format!("node {node} omitted its batch"))?,
        ));
    }
    if order_digests
        .windows(2)
        .any(|pair| pair.first() != pair.get(1))
    {
        return Err("honest resident nodes derived different simultaneous-RFQ orders".into());
    }
    for client in 0..N_CLIENTS {
        if admission_sequences[client]
            .windows(2)
            .any(|pair| pair[0] != pair[1])
            || admission_tickets[client]
                .windows(2)
                .any(|pair| pair[0] != pair[1])
            || admission_tickets[client].first().copied()
                != Some(principal_ticket_id(
                    slots - 1,
                    &client_identities[client].fingerprint,
                )?)
        {
            return Err(format!(
                "honest resident nodes derived different admission position for client {client}"
            ));
        }
    }
    let order_digest: [u8; 32] = hex::decode(&order_digests[0])
        .map_err(|_| "node returned malformed order digest".to_string())?
        .try_into()
        .map_err(|_| "node returned malformed order digest".to_string())?;
    let cluster_digest = cluster_batch_digest(slots - 1, order_digest, &node_batches)?;
    let trusted_admission_keys = node_public_keys
        .iter()
        .map(|keys| {
            VerifyingKey::from_bytes(&keys[2])
                .map_err(|_| "resident admission key is malformed".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let certified_admission_lanes = admission_attestations
        .iter()
        .map(|attestations| verify_admission_lane(attestations, &trusted_admission_keys))
        .collect::<Result<Vec<_>, _>>()?;
    if certified_admission_lanes
        .iter()
        .enumerate()
        .any(|(client, lane)| {
            lane.cluster_digest != cluster_digest
                || lane.order_digest != order_digest
                || lane.claim_digest != admission_claims[(slots - 1) as usize][client]
        })
    {
        return Err("certified admission lanes do not match the closed seven-node batch".into());
    }

    // Establish the threshold signing trust anchor before the RFQ epoch is
    // admitted. It is registered by DeFMI together with the eligible-policy
    // registry, rather than being trusted from a later settlement handoff.
    let mut proof_parties = (0..7)
        .map(|node| ProofPartyChild::spawn(node, &root))
        .collect::<Result<Vec<_>, _>>()?;
    let frost_session: [u8; 32] = Sha256::new()
        .chain_update(b"QOMM:FROST:DKG-SESSION:v1")
        .chain_update(cluster_digest)
        .finalize()
        .into();
    let frost_public = distributed_frost_setup(&mut proof_parties, frost_session)?;

    // The closed, seven-node-certified population reaches DeFMI before any
    // quote lane is evaluated. DeFMI consumes the opaque lanes in sequence,
    // locks Maker inventories and Taker maxima, and acknowledges only the
    // reservations that became authoritative. A rejected Taker still keeps
    // its fixed-size MPC lane, but never receives a quote proof.
    let authority = PretradeAuthorityBundle {
        created_at: now,
        venue_id,
        defmi_id,
        traded_asset_id,
        cash_asset_id,
        identity_scope: venue_scope.to_vec(),
        required_cohort: cohort.clone(),
        identity_provider: external_bundle.provider.clone(),
        identity_evidence_digest: external_kyb_evidence_digest,
        registry: kyb_registry.clone(),
        admission: Some(PretradeAdmission {
            epoch: 1,
            node_keys: node_public_keys.iter().map(|keys| keys[2]).collect(),
            lanes: admission_attestations.clone(),
        }),
        settlement_verifier: PretradeSettlementVerifier {
            epoch: 1,
            quote_registry_digest: prepared.quote_registry_digest,
            quote_eligibility_bits: 32,
            quote_span_bits: 32,
            amount_bits: 16,
            price_bits: 32,
            max_horizon: 3_600,
            frost_public: frost_public.clone(),
            valid_from: now.saturating_sub(1).max(1),
            valid_until: now.saturating_add(3_600),
        },
        makers: maker_authorities.clone(),
        takers: taker_authorities.clone(),
    };
    let authority_digest = authority.digest()?;
    write_authority_private(pretrade_authority_out, &authority)?;
    println!(
        "private pre-trade authority: {}",
        pretrade_authority_out.display()
    );
    let pretrade_ack = wait_for_pretrade_ack(pretrade_ack_in, pretrade_ack_timeout)?;
    let trusted_defmi = VerifyingKey::from_bytes(&acceptance_defmi_receipt_public())
        .map_err(|_| "acceptance DeFMI receipt key is malformed".to_string())?;
    pretrade_ack.verify(&trusted_defmi)?;
    if pretrade_ack.authority_digest != authority_digest || pretrade_ack.defmi_id != defmi_id {
        return Err("DeFMI acknowledgement names another pre-trade authority".into());
    }

    let mut acknowledged_makers = BTreeSet::new();
    let mut accepted_clients = BTreeSet::new();
    for binding in &pretrade_ack.bindings {
        match binding.party {
            ReservationParty::Maker => {
                let maker = maker_authorities
                    .iter()
                    .find(|authority| {
                        authority.maker_index == binding.owner_index
                            && authority.mandate.direction == binding.direction
                    })
                    .ok_or_else(|| "DeFMI acknowledged an unknown Maker reservation".to_string())?;
                if binding.owner_handle != maker.mandate.maker_handle
                    || binding.reserve_id != maker.mandate.reserve_id
                    || binding.mandate_digest != maker.mandate.digest()?
                    || binding.policy_digest != maker.mandate.policy_digest
                    || binding.amount_commitment != maker.mandate.maximum_amount_commitment
                {
                    return Err("DeFMI Maker acknowledgement differs from its mandate".into());
                }
                if !acknowledged_makers.insert((binding.owner_index, binding.direction as u8)) {
                    return Err("DeFMI acknowledged one Maker reservation twice".into());
                }
            }
            ReservationParty::Taker => {
                let taker = taker_authorities
                    .iter()
                    .find(|authority| authority.client_index == binding.owner_index)
                    .ok_or_else(|| "DeFMI acknowledged an unknown Taker reservation".to_string())?;
                if binding.direction != taker.mandate.direction
                    || binding.owner_handle != taker.mandate.taker_handle
                    || binding.reserve_id != taker.mandate.reserve_id
                    || binding.mandate_digest != taker.mandate.digest()?
                    || binding.policy_digest != [0_u8; 32]
                    || binding.amount_commitment != taker.mandate.maximum_amount_commitment
                {
                    return Err("DeFMI Taker acknowledgement differs from its mandate".into());
                }
                if !accepted_clients.insert(usize::from(binding.owner_index)) {
                    return Err("DeFMI acknowledged one Taker reservation twice".into());
                }
            }
        }
    }
    if acknowledged_makers.len() != maker_authorities.len()
        || !accepted_clients.contains(&0)
        || accepted_clients.len() != 2
        || accepted_clients.contains(&3)
        || accepted_clients.contains(&1) == accepted_clients.contains(&2)
    {
        return Err(
            "pre-trade acceptance must reserve every Maker, the seller, and exactly one shared-cap buyer"
                .into(),
        );
    }

    // Run every content-independent admission lane. Real and cover frames
    // therefore have the same MPC schedule, while RFQs that arrived in one
    // epoch are evaluated in the agreed admission order instead of being added
    // into one malformed query.
    let mut execution_lanes = (0..N_CLIENTS).map(|_| Vec::new()).collect::<Vec<_>>();
    let mut execution_digests = [[0_u8; 32]; N_CLIENTS];
    for lane in 0..N_CLIENTS {
        let mut handles = Vec::with_capacity(coordinators.len());
        for (node, mut coordinator) in coordinators.into_iter().enumerate() {
            let shape_digest = shape_digest.clone();
            handles.push(std::thread::spawn(move || {
                let response = coordinator.call(&json!({
                    "version": 1,
                    "request_id": format!("compute-final-lane-{lane}"),
                    "operation": "compute",
                    "slot": slots - 1,
                    "lane": lane,
                    "shape_digest": shape_digest,
                }));
                (node, coordinator, response)
            }));
        }
        let mut completed = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| "resident compute client thread panicked".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        completed.sort_by_key(|(node, _, _)| *node);
        coordinators = Vec::with_capacity(completed.len());
        for (node, coordinator, response) in completed {
            let response = response?;
            if response.get("ok").and_then(Value::as_bool) != Some(true) {
                return Err(format!(
                    "node {node} computation for admission lane {lane} failed: {response}"
                ));
            }
            let fixed32 = |name: &str| -> Result<[u8; 32], String> {
                hex::decode(
                    response
                        .get(name)
                        .and_then(Value::as_str)
                        .ok_or_else(|| format!("node {node} omitted {name}"))?,
                )
                .map_err(|_| format!("node {node} returned malformed {name}"))?
                .try_into()
                .map_err(|_| format!("node {node} returned malformed {name}"))
            };
            let signature: [u8; 64] = hex::decode(
                response
                    .get("mpc_execution_attestation")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("node {node} omitted its execution attestation"))?,
            )
            .map_err(|_| format!("node {node} execution attestation is malformed"))?
            .try_into()
            .map_err(|_| format!("node {node} execution attestation is malformed"))?;
            let attestation = NodeExecutionAttestation {
                node: u16::try_from(node)
                    .map_err(|_| "resident node index is outside u16".to_string())?,
                slot: u64::from(slots - 1),
                lane: lane as u64,
                batch_digest: fixed32("batch_digest")?,
                source_digest: fixed32("mpc_source_digest")?,
                state_generation: response
                    .get("mpc_state_generation")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("node {node} omitted its MPC state generation"))?,
                frame_count: response
                    .get("mpc_frame_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("node {node} omitted its MPC frame count"))?,
                input_count: response
                    .get("mpc_input_count")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("node {node} omitted its MPC input count"))?,
                stdout_digest: fixed32("mpc_stdout_digest")?,
                stderr_digest: fixed32("mpc_stderr_digest")?,
                persistence_digest: fixed32("mpc_persistence_digest")?,
                receipt_digest: fixed32("mpc_execution_digest")?,
                signature: Signature::from_bytes(&signature),
            };
            if !attestation.verify(&trusted_admission_keys[node]) {
                return Err(format!(
                    "node {node} signed an invalid MPC execution attestation"
                ));
            }
            execution_lanes[lane].push(attestation);
            coordinators.push(coordinator);
        }
        let execution = verify_execution_lane(
            &execution_lanes[lane],
            &trusted_admission_keys,
            order_digest,
        )?;
        if execution.slot != u64::from(slots - 1)
            || execution.lane != lane as u64
            || execution.cluster_digest != cluster_digest
        {
            return Err(format!(
                "MPC execution receipts for lane {lane} differ from the admitted batch"
            ));
        }
        execution_digests[lane] = execution.digest;
    }
    let mut accepted_clients_by_order = accepted_clients.into_iter().collect::<Vec<_>>();
    accepted_clients_by_order.sort_by_key(|client| admission_sequences[*client][0]);
    let mut live_proofs = Vec::new();
    for client in accepted_clients_by_order {
        let lane = admission_sequences[client][0]
            .checked_sub(1)
            .and_then(|lane| usize::try_from(lane).ok())
            .ok_or_else(|| "admission sequence cannot identify a proof lane".to_string())?;
        let quote_digest = execution_digests[lane];
        let limit_direction = if client == 0 {
            PriceLimitDirection::MinimumSellPrice
        } else {
            PriceLimitDirection::MaximumBuyPrice
        };
        let limit_value = if client == 0 { 0 } else { 1_000_000 };
        let limit_commitment = Pedersen::new(b"qomm:defmi:v1")
            .commit_u64(limit_value, &Scalar::from(101_u64 + client as u64));
        let limit_context = admission_claims[(slots - 1) as usize][client];
        live_proofs.push((
            client,
            prove_persistence_lane(
                &root,
                &prepared,
                &mut proof_parties,
                &frost_public,
                slots - 1,
                lane,
                &node_batches,
                admission_sequences[client][0],
                admission_tickets[client][0],
                quote_digest,
                i64::try_from(10 + 5 * client).map_err(|_| "quote quantity exceeds i64")?,
                151 + client as u64,
                if client == 0 { 1 } else { 0 },
                limit_direction,
                limit_commitment,
                limit_context,
                CompressedRistretto(taker_mandates[client].taker_handle)
                    .decompress()
                    .ok_or_else(|| "signed Taker mandate contains an invalid handle".to_string())?,
                now,
            )?,
        ));
    }
    for (client, proof) in &live_proofs {
        let mandate = &taker_mandates[*client];
        let mandate_digest = mandate.digest()?;
        if proof.instruction.amount_commitment.compress().to_bytes() != mandate.quantity_commitment
            || proof.limit_commitment != mandate.limit_price_commitment
            || proof.asset_id != mandate.asset_id
            || proof.admission_ticket_id != mandate.admission_ticket_id
            || proof.limit_context != mandate_digest
            || admission_claims[(slots - 1) as usize][*client] != mandate_digest
            || proof.instruction.deadline > mandate.deadline
        {
            return Err(format!(
                "RFQ {client} MPC proof differs from its pre-submission Taker mandate"
            ));
        }
        let taker_handle = CompressedRistretto(mandate.taker_handle)
            .decompress()
            .ok_or_else(|| format!("RFQ {client} Taker handle is invalid"))?;
        let handles_match = match mandate.direction {
            Direction::TakerBuys => {
                proof.instruction.payer_handle == taker_handle
                    && proof.instruction.payee_handle != taker_handle
            }
            Direction::TakerSells => {
                proof.instruction.payer_handle != taker_handle
                    && proof.instruction.payee_handle == taker_handle
            }
        };
        if !handles_match {
            return Err(format!(
                "RFQ {client} cash payer/payee roles disagree with its signed direction"
            ));
        }
    }
    let restart_probe: [u8; 32] = Sha256::new()
        .chain_update(b"QOMM:FROST:HEALTH:v1")
        .chain_update(frost_session)
        .chain_update([1_u8])
        .chain_update(cluster_digest)
        .finalize()
        .into();
    authorize_health_signing(
        &mut proof_parties,
        &[1, 4, 7],
        "pre-restart",
        cluster_digest,
        &restart_probe,
    )?;
    let restart_signature = distributed_frost_sign(
        &mut proof_parties,
        &[1, 4, 7],
        &restart_probe,
        &frost_public,
    )?;
    frost_public
        .verifying_key()
        .verify(&restart_probe, &restart_signature)
        .map_err(|_| "FROST pre-restart probe signature is invalid")?;
    let public_before_restart = frost_public
        .serialize()
        .map_err(|_| "FROST public package serialization failed")?;
    for party in proof_parties {
        party.finish()?;
    }
    let mut proof_parties = (0..7)
        .map(|node| ProofPartyChild::spawn(node, &root))
        .collect::<Result<Vec<_>, _>>()?;
    let recovered_public = distributed_frost_setup(&mut proof_parties, frost_session)?;
    if recovered_public
        .serialize()
        .map_err(|_| "FROST recovered public package serialization failed")?
        != public_before_restart
    {
        return Err("FROST group public key changed across proof-node restart".into());
    }
    let persisted_replay = proof_parties[0].call(
        "frost_commit",
        json!({
            "job_id": hex::encode(frost_signing_job(&restart_probe)),
            "message": BASE64.encode(restart_probe),
        }),
    );
    if persisted_replay.is_ok() {
        return Err("FROST consumed signing job became reusable after restart".into());
    }
    let unauthorized_probe: [u8; 64] = Sha512::new()
        .chain_update(b"QOMM:FROST:UNAUTHORIZED-ACCEPTANCE-PROBE:v1")
        .chain_update(frost_session)
        .chain_update(cluster_digest)
        .finalize()
        .into();
    let arbitrary_signing_refused = proof_parties.iter_mut().all(|party| {
        party
            .call(
                "frost_commit",
                json!({
                    "job_id": hex::encode(frost_signing_job(&unauthorized_probe)),
                    "message": BASE64.encode(unauthorized_probe),
                }),
            )
            .is_err()
    });
    if !arbitrary_signing_refused {
        return Err("a proof node accepted an unauthorized FROST signing request".into());
    }
    let post_restart_probe: [u8; 32] = Sha256::new()
        .chain_update(b"QOMM:FROST:HEALTH:v1")
        .chain_update(frost_session)
        .chain_update([2_u8])
        .chain_update(cluster_digest)
        .finalize()
        .into();
    authorize_health_signing(
        &mut proof_parties,
        &[1, 4, 7],
        "post-restart",
        cluster_digest,
        &post_restart_probe,
    )?;
    let post_restart_signature = distributed_frost_sign(
        &mut proof_parties,
        &[1, 4, 7],
        &post_restart_probe,
        &recovered_public,
    )?;
    recovered_public
        .verifying_key()
        .verify(&post_restart_probe, &post_restart_signature)
        .map_err(|_| "FROST post-restart probe signature is invalid")?;
    for party in proof_parties {
        party.finish()?;
    }
    let frost_restart_works = true;

    // The two live requests deliberately exercise opposite trade directions.
    // For a sell, the Taker's securities reservation and one winning Maker's
    // cash reservation must be selected. For a buy, the selected sides reverse.
    // Distinct Maker values/blindings make a mistaken common-reserve shortcut
    // observable without opening which Maker won.
    let reserve_key = Pedersen::new(b"qomm:defmi:v1");
    let compressed = |value: u64, blinding: u64| {
        reserve_key
            .commit(&Scalar::from(value), &Scalar::from(blinding))
            .compress()
            .to_bytes()
    };
    let taker_securities = compressed(TAKER_SECURITIES.0, TAKER_SECURITIES.1);
    let taker_cash = compressed(TAKER_CASH.0, TAKER_CASH.1);
    let maker_securities = MAKER_SECURITIES.map(|(value, blinding)| compressed(value, blinding));
    let maker_cash = MAKER_CASH.map(|(value, blinding)| compressed(value, blinding));
    for (client, proof) in &live_proofs {
        match taker_mandates[*client].direction {
            Direction::TakerSells
                if proof.securities_reserve == taker_securities
                    && maker_cash.contains(&proof.cash_reserve) => {}
            Direction::TakerBuys
                if maker_securities.contains(&proof.securities_reserve)
                    && proof.cash_reserve == taker_cash => {}
            Direction::TakerSells => {
                return Err(
                    "sell RFQ did not select Taker securities plus winning Maker cash".into(),
                );
            }
            Direction::TakerBuys => {
                return Err(
                    "buy RFQ did not select winning Maker securities plus Taker cash".into(),
                );
            }
        }
    }

    let transport_mode = if transports
        .iter()
        .all(|transport| matches!(transport, Transport::Tcp))
    {
        "tcp-mtls"
    } else {
        "socket-pair-mtls (bind unavailable)"
    };
    println!("transport: {transport_mode}");
    println!("fixed KYB-scoped participants per node: {N_CLIENTS}");
    println!("frames across seven nodes per slot: {slot_counts:?}");
    println!("frames per slot constant: {}", yes_no(frames_constant));
    println!("all nodes use the same RFQ order: yes");
    println!(
        "real RFQ admission sequence agreed by all nodes: {}",
        admission_sequences[0][0]
    );
    println!(
        "second simultaneous RFQ admission sequence agreed by all nodes: {}",
        admission_sequences[1][0]
    );
    println!("seven-node batch binding: {}", hex::encode(cluster_digest));
    for (client, proof) in &live_proofs {
        println!(
            "RFQ {client} MPC->zkPI proof: instruction={} quote={} limit={} limit-proof={} limit-context={} securities-reserve={} cash-reserve={} cash={} range-proof-bytes={}",
            hex::encode(proof.instruction_digest),
            hex::encode(proof.quote_digest),
            hex::encode(proof.limit_commitment),
            hex::encode(proof.price_limit_proof_digest),
            hex::encode(proof.limit_context),
            hex::encode(proof.securities_reserve),
            hex::encode(proof.cash_reserve),
            hex::encode(proof.cash_commitment),
            proof.range_proof_bytes,
        );
    }
    println!("recovery works: {}", yes_no(recovery_works));
    println!(
        "sealing identities survive restart: {}",
        yes_no(sealing_key_recovery_works)
    );
    println!(
        "FROST identity, key shares, and consumed jobs survive restart: {}",
        yes_no(frost_restart_works)
    );
    println!(
        "all proof nodes refuse arbitrary FROST signing after restart: {}",
        yes_no(arbitrary_signing_refused)
    );
    println!(
        "repeated id with a different body refused: {}",
        yes_no(different_body_refused)
    );
    println!(
        "cover and real frames the same size: {}",
        yes_no(cover_real_same_size)
    );
    if let Some(path) = evidence_out {
        let source_digest: [u8; 32] = hex::decode(&prepared.source_digest)
            .map_err(|_| "MPC source digest is malformed".to_string())?
            .try_into()
            .map_err(|_| "MPC source digest is malformed".to_string())?;
        let bundle = SettlementHandoffBundle {
            created_at: now,
            source_digest,
            cluster_digest,
            order_digest,
            admission_batch_digest: cluster_digest,
            slot: slots - 1,
            admission_node_keys: node_public_keys.iter().map(|keys| keys[2]).collect(),
            admission_lanes: admission_attestations,
            execution_lanes,
            records: live_proofs
                .into_iter()
                .map(|(_, proof)| proof.into_handoff(frost_public.clone()))
                .collect(),
        };
        write_settlement_handoff(path, &bundle)?;
        println!("private DeFMI handoff: {}", path.display());
    }

    for entity_clients in &mut clients {
        for client in entity_clients {
            client.close();
        }
    }
    for coordinator in &mut coordinators {
        coordinator.close();
    }
    for server in &mut servers {
        server.stop();
    }
    Ok(frames_constant
        && recovery_works
        && sealing_key_recovery_works
        && frost_restart_works
        && arbitrary_signing_refused
        && different_body_refused
        && cover_real_same_size)
}

fn finalize_settlement_handoff(
    proof_root: &Path,
    handoff_path: &Path,
    contexts_path: &Path,
    pretrade_ack_path: &Path,
    output_path: &Path,
) -> Result<(), String> {
    let mut handoff = read_settlement_handoff(handoff_path)?;
    let contexts = read_finalization_contexts(contexts_path, &handoff)?;
    let pretrade_ack = read_ack_private(pretrade_ack_path)?;
    let trusted_defmi = VerifyingKey::from_bytes(&acceptance_defmi_receipt_public())
        .map_err(|_| "acceptance DeFMI receipt key is malformed".to_string())?;
    pretrade_ack.verify(&trusted_defmi)?;
    let pretrade_ack_wire = encode_ack(&pretrade_ack)?;
    let mut proof_parties = (0..7)
        .map(|node| ProofPartyChild::spawn(node, proof_root))
        .collect::<Result<Vec<_>, _>>()?;
    let selected = [1_usize, 4, 7];
    for record in &mut handoff.records {
        if record.execution_context.is_some() || record.typed_authorization.is_some() {
            return Err("settlement handoff was already finalized".into());
        }
        let context = contexts
            .get(&record.job_id)
            .cloned()
            .ok_or_else(|| "finalization omitted a handoff job".to_string())?;
        let message = typed::digest_for(&record.instruction, &context, DEFAULT_DOMAIN)
            .map_err(str::to_string)?;
        let signing_job = frost_signing_job(&message);
        let payment_wire = qomm_zkpi::wire::encode(&record.instruction);
        let context_wire = typed_wire::encode_context(&context);
        for party in selected {
            proof_parties[party - 1].call(
                "authorize_typed",
                json!({
                    "job_id": hex::encode(record.job_id),
                    "signing_job_id": hex::encode(signing_job),
                    "message": BASE64.encode(message),
                    "payment": BASE64.encode(&payment_wire),
                    "context": BASE64.encode(&context_wire),
                    "pretrade_ack": BASE64.encode(&pretrade_ack_wire),
                }),
            )?;
        }
        let authorization = distributed_frost_sign(
            &mut proof_parties,
            &selected,
            &message,
            &record.frost_public,
        )?;
        record
            .frost_public
            .verifying_key()
            .verify(&message, &authorization)
            .map_err(|_| "finalized typed zkPI signature is invalid")?;
        record.execution_context = Some(context);
        record.typed_authorization = Some(authorization);
        record.typed_instruction()?;
    }
    write_settlement_handoff(output_path, &handoff)?;
    for party in proof_parties {
        party.finish()?;
    }
    println!(
        "finalized {} MPC zkPI record(s) for DeFMI: {}",
        handoff.records.len(),
        output_path.display()
    );
    Ok(())
}

fn main() {
    let mut slots = 5_u32;
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.iter().any(|argument| argument == "--proof-party") {
        if let Err(error) = run_proof_party(&arguments) {
            eprintln!("proof party failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--finalize-handoff")
    {
        let path = |name: &str| -> Result<PathBuf, String> {
            arguments
                .iter()
                .position(|argument| argument == name)
                .and_then(|position| arguments.get(position + 1))
                .map(PathBuf::from)
                .ok_or_else(|| format!("handoff finalization requires {name}"))
        };
        let result = path("--proof-root").and_then(|proof_root| {
            path("--handoff").and_then(|handoff| {
                path("--contexts").and_then(|contexts| {
                    path("--pretrade-ack").and_then(|pretrade_ack| {
                        path("--finalized-out").and_then(|output| {
                            finalize_settlement_handoff(
                                &proof_root,
                                &handoff,
                                &contexts,
                                &pretrade_ack,
                                &output,
                            )
                        })
                    })
                })
            })
        });
        if let Err(error) = result {
            eprintln!("settlement handoff finalization failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Some(position) = arguments.iter().position(|argument| argument == "--slots") {
        slots = arguments
            .get(position + 1)
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| {
                eprintln!("--slots requires an unsigned integer");
                std::process::exit(2);
            });
    }
    let pretrade_ack_timeout_seconds = arguments
        .iter()
        .position(|argument| argument == "--pretrade-ack-timeout-seconds")
        .and_then(|position| arguments.get(position + 1))
        .map(|value| value.parse::<u64>())
        .transpose()
        .unwrap_or_else(|_| {
            eprintln!("--pretrade-ack-timeout-seconds requires an unsigned integer");
            std::process::exit(2);
        })
        .unwrap_or(300);
    if !(1..=3_600).contains(&pretrade_ack_timeout_seconds) {
        eprintln!("--pretrade-ack-timeout-seconds must be between 1 and 3600");
        std::process::exit(2);
    }
    let mp_spdz_root = arguments
        .iter()
        .position(|argument| argument == "--mp-spdz-root")
        .and_then(|position| arguments.get(position + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("--mp-spdz-root requires the stock MP-SPDZ checkout path");
            std::process::exit(2);
        });
    let runner = arguments
        .iter()
        .position(|argument| argument == "--runner")
        .and_then(|position| arguments.get(position + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|parent| parent.join("qomm_node_party")))
                .unwrap_or_else(|| PathBuf::from("qomm_node_party"))
        });
    let evidence_out = arguments
        .iter()
        .position(|argument| argument == "--evidence-out")
        .and_then(|position| arguments.get(position + 1))
        .map(PathBuf::from);
    let required_path = |name: &str| {
        arguments
            .iter()
            .position(|argument| argument == name)
            .and_then(|position| arguments.get(position + 1))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                eprintln!("{name} is required; quote evaluation cannot precede DeFMI reservation");
                std::process::exit(2);
            })
    };
    let pretrade_authority_out = required_path("--pretrade-authority-out");
    let pretrade_ack_in = required_path("--pretrade-ack-in");
    let external_kyb_trust_anchor = required_path("--external-kyb-trust-anchor");
    let external_kyb_bundle = required_path("--external-kyb-bundle");
    match run(AcceptanceConfig {
        slots,
        pretrade_ack_timeout: Duration::from_secs(pretrade_ack_timeout_seconds),
        mp_spdz_root: &mp_spdz_root,
        runner: &runner,
        evidence_out: evidence_out.as_deref(),
        pretrade_authority_out: &pretrade_authority_out,
        pretrade_ack_in: &pretrade_ack_in,
        external_kyb_trust_anchor: &external_kyb_trust_anchor,
        external_kyb_bundle: &external_kyb_bundle,
    }) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("seven-node acceptance failed: {error}");
            std::process::exit(1);
        }
    }
}
