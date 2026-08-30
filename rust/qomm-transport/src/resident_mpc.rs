//! Node-local handoff from a sealed fixed-population slot to stock MP-SPDZ.
//!
//! The node sees only its additive input shares.  Maker-policy and reservation
//! shares live in an authenticated encrypted store; Taker shares arrive in the
//! fixed-size frames already authenticated by `node_service`.  One runner
//! process writes exactly one party input, starts exactly one stock MP-SPDZ
//! party, and retains only that party's Persistence output.

use crate::key_management::{
    decrypt_authenticated, derive_secret_key, encrypt_authenticated, FileLock,
};
use crate::wire::{FieldElement, Frame, FRAME_BYTES};
use qomm_mpc::inputs::DvpInputs;
use qomm_mpc::persistence::FieldElement as DecimalFieldElement;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        hex::decode(&value)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("digest must contain exactly 32 bytes"))
    }
}

const SEALED_MAGIC: &[u8] = b"QOMM:SEALED:BATCH:v1";
const EXECUTION_RECEIPT_DOMAIN: &[u8] = b"QOMM:MPC:EXECUTION-RECEIPT:v1";
const STATE_MAGIC: &[u8; 8] = b"QOMMMPC1";
const STATE_AAD: &[u8] = b"QOMM:MPC-SECRET-STATE:v1";
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const MAX_FRAMES: usize = 4096;
// asset, quantity, direction, entity, real/cover flag, response mask,
// committed limit, secret limit blinding, fill mask, quantity commitment
// blinding, then the Taker's securities reserve, its blinding, cash reserve,
// and its blinding. The latter four are per-RFQ values bound to the signed
// pre-trade acknowledgement; they must not live in standing Maker state.
const REQUEST_VALUES: usize = 14;
const REQUEST_PUBLIC_AND_ADMISSION_VALUES: usize = 6;
const REQUEST_LIMIT_VALUES_START: usize = 6;
const REQUEST_LIMIT_VALUES_END: usize = 10;
const REQUEST_TAKER_DVP_START: usize = 10;
const POLICY_FIELDS: usize = 10;
const QUOTE_POLICY_BLINDING_FIELDS: usize = 9;
const ED25519_ORDER: &str =
    "7237005577332262213973186563042994240857116359379907606001950938285454250989";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MpcSecretState {
    pub version: u8,
    pub node: u16,
    pub generation: u64,
    pub source_sha256: String,
    /// Local shares, in circuit order, for every Maker's two standing reserve
    /// rails and settlement handle. Taker reserve shares arrive in each signed
    /// RFQ frame, so arbitrary pre-authorized Takers do not have to share one
    /// long-lived amount or blinding.
    pub dvp_input_shares: Vec<String>,
    /// Ten local shares per Maker, in `qomm_mpc::program::FIELDS` order.
    pub policy_input_shares: Vec<String>,
    /// Nine registered Pedersen-blinding shares per Maker. Empty for legacy
    /// circuits; complete quote-proof circuits require exactly this vector.
    #[serde(default)]
    pub quote_policy_blinding_input_shares: Vec<String>,
}

impl MpcSecretState {
    pub fn verify(&self, node: u16, source_sha256: &str, n_mm: usize) -> Result<(), String> {
        if self.version != 1
            || self.node != node
            || self.source_sha256 != source_sha256
            || !is_digest(&self.source_sha256)
            || self.dvp_input_shares.len() != DvpInputs::standing_value_count(n_mm)
            || self.policy_input_shares.len() != n_mm.saturating_mul(POLICY_FIELDS)
            || !(self.quote_policy_blinding_input_shares.is_empty()
                || self.quote_policy_blinding_input_shares.len()
                    == n_mm.saturating_mul(QUOTE_POLICY_BLINDING_FIELDS))
            || self
                .dvp_input_shares
                .iter()
                .chain(&self.policy_input_shares)
                .chain(&self.quote_policy_blinding_input_shares)
                .any(|value| !is_decimal(value))
        {
            return Err(
                "encrypted MPC state does not match the approved node/circuit shape".into(),
            );
        }
        Ok(())
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_decimal(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty()
        && digits.len() <= 80
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && value != "-0"
}

pub struct EncryptedMpcStateStore {
    pub path: PathBuf,
    passphrase: Vec<u8>,
}

impl fmt::Debug for EncryptedMpcStateStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedMpcStateStore")
            .field("path", &self.path)
            .field("passphrase", &"[redacted]")
            .finish()
    }
}

impl EncryptedMpcStateStore {
    pub fn new(path: impl Into<PathBuf>, passphrase: &[u8]) -> Result<Self, String> {
        if passphrase.len() < 12 {
            return Err("MPC-state passphrase must contain at least 12 bytes".into());
        }
        Ok(Self {
            path: path.into(),
            passphrase: passphrase.to_vec(),
        })
    }

    pub fn initialize(&self, state: &MpcSecretState) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let _lock = FileLock::acquire(&self.path)?;
        if self.path.exists() {
            return Err(format!("{} already exists", self.path.display()));
        }
        self.write_unlocked(state)
    }

    pub fn load(&self) -> Result<MpcSecretState, String> {
        let _lock = FileLock::acquire(&self.path)?;
        let metadata = self.path.metadata().map_err(|error| error.to_string())?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "refusing MPC secret state with mode {mode:o}; expected 600"
            ));
        }
        let raw = fs::read(&self.path).map_err(|error| error.to_string())?;
        let minimum = STATE_MAGIC.len() + SALT_BYTES + NONCE_BYTES + 16;
        if raw.len() < minimum || raw.get(..STATE_MAGIC.len()) != Some(STATE_MAGIC) {
            return Err("not a QOMM encrypted MPC state".into());
        }
        let salt = &raw[STATE_MAGIC.len()..STATE_MAGIC.len() + SALT_BYTES];
        let nonce_start = STATE_MAGIC.len() + SALT_BYTES;
        let nonce: &[u8; NONCE_BYTES] = raw[nonce_start..nonce_start + NONCE_BYTES]
            .try_into()
            .expect("fixed nonce");
        let clear = decrypt_authenticated(
            &derive_secret_key(&self.passphrase, salt)?,
            nonce,
            STATE_AAD,
            &raw[nonce_start + NONCE_BYTES..],
        )?;
        serde_json::from_slice(&clear)
            .map_err(|_| "MPC-state authentication succeeded but its payload is malformed".into())
    }

    fn write_unlocked(&self, state: &MpcSecretState) -> Result<(), String> {
        let mut salt = [0_u8; SALT_BYTES];
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let clear = serde_json::to_vec(state).map_err(|error| error.to_string())?;
        let encrypted = encrypt_authenticated(
            &derive_secret_key(&self.passphrase, &salt)?,
            &nonce,
            STATE_AAD,
            &clear,
        )?;
        let mut raw =
            Vec::with_capacity(STATE_MAGIC.len() + SALT_BYTES + NONCE_BYTES + encrypted.len());
        raw.extend_from_slice(STATE_MAGIC);
        raw.extend_from_slice(&salt);
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&encrypted);
        atomic_private_write(&self.path, &raw)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResidentMpcConfig {
    pub version: u8,
    pub node: u16,
    pub n_parties: u16,
    pub threshold: u16,
    pub n_mm: usize,
    pub mp_spdz_root: PathBuf,
    /// Node-local MP-SPDZ TLS directory. It contains every party's public
    /// certificate but only this node's private key.
    pub player_data_root: PathBuf,
    pub run_root: PathBuf,
    pub program: String,
    pub source_sha256: String,
    pub host_file: PathBuf,
    pub host_file_sha256: String,
    pub party_binary: PathBuf,
    pub party_binary_sha256: String,
    pub library: PathBuf,
    pub library_sha256: String,
    /// TLS certificates, private keys, and OpenSSL subject-hash links used by
    /// the stock MP-SPDZ party transport. Keys remain node-local files and are
    /// never copied into an API response.
    pub player_data_artifacts: BTreeMap<String, String>,
    /// Relative-to-MP-SPDZ paths for the source, schedule and every bytecode
    /// tape accepted by this deployment.
    pub program_artifacts: BTreeMap<String, String>,
    pub state_store: PathBuf,
    pub passphrase_file: PathBuf,
    pub prime: String,
    pub timeout_seconds: f64,
}

impl ResidentMpcConfig {
    pub fn verify(&self, expected_source: &str) -> Result<(), String> {
        if self.version != 1
            || self.n_parties != 7
            || self.threshold != 2
            || self.node >= self.n_parties
            || self.n_mm == 0
            || !self.n_mm.is_power_of_two()
            || self.prime != ED25519_ORDER
            || self.source_sha256 != expected_source
            || !is_digest(&self.source_sha256)
            || !(0.0 < self.timeout_seconds && self.timeout_seconds <= 3600.0)
            || !valid_program_name(&self.program)
        {
            return Err("resident MPC configuration has an unsupported circuit or quorum".into());
        }
        for path in [
            &self.mp_spdz_root,
            &self.player_data_root,
            &self.run_root,
            &self.host_file,
            &self.party_binary,
            &self.library,
            &self.state_store,
            &self.passphrase_file,
        ] {
            if !path.is_absolute() {
                return Err(format!(
                    "resident MPC path must be absolute: {}",
                    path.display()
                ));
            }
        }
        verify_digest_file(&self.host_file, &self.host_file_sha256, false)?;
        verify_digest_file(&self.party_binary, &self.party_binary_sha256, true)?;
        verify_digest_file(&self.library, &self.library_sha256, false)?;
        protected_file(&self.passphrase_file, "MPC-state passphrase")?;
        protected_file(&self.state_store, "encrypted MPC state")?;
        let source = format!("Programs/Source/{}.mpc", self.program);
        let schedule = format!("Programs/Schedules/{}.sch", self.program);
        if self.program_artifacts.get(&source) != Some(&self.source_sha256)
            || !self.program_artifacts.contains_key(&schedule)
            || !self
                .program_artifacts
                .keys()
                .any(|path| path.starts_with(&format!("Programs/Bytecode/{}-", self.program)))
        {
            return Err("resident MPC manifest omits source, schedule, or bytecode".into());
        }
        for (relative, digest) in &self.program_artifacts {
            if !safe_relative(relative) {
                return Err("resident MPC artifact path is not a safe relative path".into());
            }
            verify_digest_file(&self.mp_spdz_root.join(relative), digest, false)?;
        }
        for party in 0..self.n_parties {
            let name = format!("P{party}.pem");
            if !self.player_data_artifacts.contains_key(&name) {
                return Err(format!("resident MPC TLS manifest omits {name}"));
            }
        }
        let own_key = format!("P{}.key", self.node);
        let private_keys = self
            .player_data_artifacts
            .keys()
            .filter(|name| name.ends_with(".key"))
            .collect::<Vec<_>>();
        if private_keys.len() != 1 || private_keys[0].as_str() != own_key {
            return Err(
                "resident MPC TLS manifest must contain only this node's private key".into(),
            );
        }
        if self
            .player_data_artifacts
            .keys()
            .filter(|name| name.ends_with(".0"))
            .count()
            < usize::from(self.n_parties)
        {
            return Err("resident MPC TLS manifest omits certificate hash links".into());
        }
        for (name, digest) in &self.player_data_artifacts {
            if Path::new(name).components().count() != 1
                || !(name.starts_with('P') && (name.ends_with(".key") || name.ends_with(".pem"))
                    || name.len() == 10 && name.ends_with(".0"))
            {
                return Err("resident MPC TLS manifest contains an unsafe file name".into());
            }
            verify_digest_file(&self.player_data_root.join(name), digest, false)?;
        }
        Ok(())
    }
}

fn valid_program_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn verify_digest_file(path: &Path, expected: &str, executable: bool) -> Result<(), String> {
    if !is_digest(expected) {
        return Err(format!("invalid SHA-256 for {}", path.display()));
    }
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || (executable && metadata.permissions().mode() & 0o111 == 0) {
        return Err(format!(
            "runtime artifact is missing or has the wrong type: {}",
            path.display()
        ));
    }
    let actual = hex::encode(Sha256::digest(
        fs::read(path).map_err(|error| error.to_string())?,
    ));
    if actual != expected {
        return Err(format!(
            "runtime artifact digest changed: {}",
            path.display()
        ));
    }
    Ok(())
}

fn protected_file(path: &Path, name: &str) -> Result<(), String> {
    let metadata = path.metadata().map_err(|error| error.to_string())?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file() || mode & 0o077 != 0 {
        return Err(format!("{name} {} must be a mode-600 file", path.display()));
    }
    Ok(())
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("qomm"),
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub fn decode_sealed_batch(
    raw: &[u8],
    node: u16,
    slot: u32,
    expected_digest: &[u8; 32],
) -> Result<Vec<Frame>, String> {
    if Sha256::digest(raw).as_slice() != expected_digest {
        return Err("sealed stdin does not match the coordinator's batch digest".into());
    }
    if !raw.starts_with(SEALED_MAGIC) {
        return Err("sealed stdin has the wrong magic".into());
    }
    let mut at = SEALED_MAGIC.len();
    let stored_slot = take_u32(raw, &mut at)?;
    if stored_slot != slot {
        return Err("sealed stdin belongs to another slot".into());
    }
    let count = usize::try_from(take_u32(raw, &mut at)?)
        .map_err(|_| "sealed frame count overflow".to_string())?;
    if count == 0 || count > MAX_FRAMES {
        return Err("sealed frame count is outside its fixed-population bound".into());
    }
    let mut frames = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::try_from(take_u32(raw, &mut at)?)
            .map_err(|_| "sealed frame length overflow".to_string())?;
        if length != FRAME_BYTES || raw.len().saturating_sub(at) < length {
            return Err("sealed frame has the wrong fixed size".into());
        }
        let frame = Frame::decode(&raw[at..at + length]).map_err(|error| error.to_string())?;
        at += length;
        if frame.node != node || frame.slot != slot {
            return Err("sealed frame belongs to another node or slot".into());
        }
        frames.push(frame);
    }
    if at != raw.len() {
        return Err("sealed stdin has trailing bytes".into());
    }
    Ok(frames)
}

fn take_u32(raw: &[u8], at: &mut usize) -> Result<u32, String> {
    if raw.len().saturating_sub(*at) < 4 {
        return Err("sealed stdin is truncated".into());
    }
    let value = u32::from_be_bytes(raw[*at..*at + 4].try_into().expect("four bytes"));
    *at += 4;
    Ok(value)
}

pub fn aggregate_request_shares(frames: &[Frame]) -> Result<Vec<FieldElement>, String> {
    if frames.is_empty() {
        return Err("a sealed slot has no fixed-population frames".into());
    }
    let mut totals = vec![FieldElement::ZERO; REQUEST_VALUES];
    for frame in frames {
        for (index, total) in totals.iter_mut().enumerate() {
            let start = index * 32;
            let share = FieldElement::from_be_bytes(
                frame.payload[start..start + 32]
                    .try_into()
                    .expect("fixed field element"),
            )
            .map_err(|error| error.to_string())?;
            *total = total.add_mod(share);
        }
    }
    Ok(totals)
}

/// Read one content-independent admission lane. Every registered participant
/// contributes a same-size real-or-cover frame; running every lane in order
/// supports simultaneous RFQs without adding their secret queries together.
pub fn request_shares_for_lane(frames: &[Frame], lane: usize) -> Result<Vec<FieldElement>, String> {
    let frame = frames
        .get(lane)
        .ok_or_else(|| "computation lane is outside the sealed fixed population".to_string())?;
    (0..REQUEST_VALUES)
        .map(|index| {
            let start = index * 32;
            FieldElement::from_be_bytes(
                frame.payload[start..start + 32]
                    .try_into()
                    .expect("fixed field element"),
            )
            .map_err(|error| error.to_string())
        })
        .collect()
}

pub fn assemble_party_input(
    request: &[FieldElement],
    state: &MpcSecretState,
    n_mm: usize,
) -> Result<Vec<String>, String> {
    if request.len() != REQUEST_VALUES {
        return Err("resident request share vector has the wrong width".into());
    }
    state.verify(state.node, &state.source_sha256, n_mm)?;
    let decimal =
        |value: FieldElement| DecimalFieldElement::from_bytes_be(&value.to_be_bytes()).to_string();
    let mut inputs = request[..REQUEST_PUBLIC_AND_ADMISSION_VALUES]
        .iter()
        .copied()
        .map(decimal)
        .collect::<Vec<_>>();
    inputs.extend(
        request[REQUEST_TAKER_DVP_START..]
            .iter()
            .copied()
            .map(decimal),
    );
    inputs.extend(state.dvp_input_shares.iter().cloned());
    inputs.extend(
        request[REQUEST_LIMIT_VALUES_START..REQUEST_LIMIT_VALUES_END]
            .iter()
            .copied()
            .map(decimal),
    );
    inputs.extend(state.policy_input_shares.iter().cloned());
    inputs.extend(state.quote_policy_blinding_input_shares.iter().cloned());
    Ok(inputs)
}

pub fn execute_resident_party(
    config: &ResidentMpcConfig,
    slot: u32,
    lane: usize,
    batch_digest: [u8; 32],
    source_digest: &str,
    sealed: &[u8],
) -> Result<ResidentExecutionReceipt, String> {
    config.verify(source_digest)?;
    let passphrase = read_private_secret(&config.passphrase_file)?;
    let state_store = EncryptedMpcStateStore::new(&config.state_store, &passphrase)?;
    let state = state_store.load()?;
    state.verify(config.node, source_digest, config.n_mm)?;
    let frames = decode_sealed_batch(sealed, config.node, slot, &batch_digest)?;
    let request = request_shares_for_lane(&frames, lane)?;
    let inputs = assemble_party_input(&request, &state, config.n_mm)?;

    let run_dir = config
        .run_root
        .join(&config.source_sha256[..16])
        .join(format!("slot-{slot:010}"))
        .join(format!("lane-{lane:04}"))
        .join(hex::encode(batch_digest))
        .join(format!("node-{}", config.node));
    fs::create_dir_all(run_dir.join("Player-Data")).map_err(|error| error.to_string())?;
    fs::create_dir_all(run_dir.join("Persistence")).map_err(|error| error.to_string())?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let programs = run_dir.join("Programs");
    if !programs.exists() {
        symlink(config.mp_spdz_root.join("Programs"), &programs)
            .map_err(|error| error.to_string())?;
    }
    for name in config.player_data_artifacts.keys() {
        let target = run_dir.join("Player-Data").join(name);
        if !target.exists() {
            symlink(config.player_data_root.join(name), &target)
                .map_err(|error| error.to_string())?;
        }
    }
    let _run_lock = FileLock::acquire(&run_dir.join("execution"))?;
    let input_path = run_dir
        .join("Player-Data")
        .join(format!("Input-P{}-0", config.node));
    if input_path.exists() {
        return Err("resident MPC plaintext input survived an earlier interrupted run".into());
    }
    let mut input = inputs.join(" ").into_bytes();
    input.push(b'\n');
    atomic_private_write(&input_path, &input)?;
    input.fill(0);
    let _input_guard = PlaintextInputGuard(input_path.clone());

    let started = Instant::now();
    let mut command = Command::new(&config.party_binary);
    command
        .arg(config.node.to_string())
        .arg(&config.program)
        .args(["-N", &config.n_parties.to_string()])
        .args(["-T", &config.threshold.to_string()])
        .args(["-ip", config.host_file.to_string_lossy().as_ref()])
        .args(["-P", &config.prime])
        .current_dir(&run_dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "macos")]
    command.env("DYLD_LIBRARY_PATH", &config.mp_spdz_root);
    #[cfg(not(target_os = "macos"))]
    command.env("LD_LIBRARY_PATH", &config.mp_spdz_root);
    let mut child = command
        .spawn()
        .map_err(|error| format!("stock MP-SPDZ party failed to start: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "stock MP-SPDZ stdout was not captured".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "stock MP-SPDZ stderr was not captured".to_string())?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, 1 << 20));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, 1 << 20));
    let timeout = Duration::from_secs_f64(config.timeout_seconds);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("stock MP-SPDZ party exceeded its timeout".into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "stock MP-SPDZ stdout reader panicked".to_string())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "stock MP-SPDZ stderr reader panicked".to_string())??;
    if !status.success() {
        // Keep node-local, mode-600 diagnostics for an operator. The remote
        // coordinator receives only digests through `executor`, so MP-SPDZ
        // diagnostics and paths never cross the node boundary.
        atomic_private_write(&run_dir.join("failure.stdout"), &stdout)?;
        atomic_private_write(&run_dir.join("failure.stderr"), &stderr)?;
        return Err(format!(
            "stock MP-SPDZ party failed (stdout={}, stderr={})",
            hex::encode(Sha256::digest(&stdout)),
            hex::encode(Sha256::digest(&stderr))
        ));
    }
    let persistence = run_dir
        .join("Persistence")
        .join(format!("Transactions-P{}.data", config.node));
    protected_persistence(&persistence)?;
    Ok(ResidentExecutionReceipt {
        node: config.node,
        slot,
        lane,
        batch_digest,
        source_digest: source_digest.to_string(),
        state_generation: state.generation,
        frame_count: frames.len(),
        input_count: inputs.len(),
        elapsed_ns: started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
        stdout_digest: Sha256::digest(stdout).into(),
        stderr_digest: Sha256::digest(stderr).into(),
        persistence_path: persistence,
        persistence_digest: Sha256::digest(
            fs::read(
                run_dir
                    .join("Persistence")
                    .join(format!("Transactions-P{}.data", config.node)),
            )
            .map_err(|error| error.to_string())?,
        )
        .into(),
    })
}

fn read_private_secret(path: &Path) -> Result<Vec<u8>, String> {
    protected_file(path, "MPC-state passphrase")?;
    let mut value = fs::read(path).map_err(|error| error.to_string())?;
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        value.pop();
    }
    if value.len() < 12 {
        return Err("MPC-state passphrase file is empty or too short".into());
    }
    Ok(value)
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err("stock MP-SPDZ output exceeded its one-megabyte bound".into());
    }
    Ok(bytes)
}

fn protected_persistence(path: &Path) -> Result<(), String> {
    let metadata = path
        .metadata()
        .map_err(|error| format!("stock MP-SPDZ did not write its local proof handoff: {error}"))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err("stock MP-SPDZ wrote an empty or non-file proof handoff".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| error.to_string())
}

struct PlaintextInputGuard(PathBuf);

impl Drop for PlaintextInputGuard {
    fn drop(&mut self) {
        if let Ok(mut bytes) = fs::read(&self.0) {
            bytes.fill(0);
            let _ = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&self.0)
                .and_then(|mut file| file.write_all(&bytes));
        }
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResidentExecutionReceipt {
    pub node: u16,
    pub slot: u32,
    pub lane: usize,
    #[serde(with = "hex32")]
    pub batch_digest: [u8; 32],
    pub source_digest: String,
    pub state_generation: u64,
    pub frame_count: usize,
    pub input_count: usize,
    pub elapsed_ns: u64,
    #[serde(with = "hex32")]
    pub stdout_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub stderr_digest: [u8; 32],
    pub persistence_path: PathBuf,
    #[serde(with = "hex32")]
    pub persistence_digest: [u8; 32],
}

impl ResidentExecutionReceipt {
    /// Validate the public portion of a node-local execution receipt against
    /// the sealed request the verified runner was launched with.  The local
    /// persistence path is deliberately excluded from the public digest.
    pub fn validate_against(
        &self,
        node: u16,
        slot: u32,
        lane: usize,
        batch_digest: [u8; 32],
        source_digest: &str,
    ) -> Result<(), String> {
        if self.node != node
            || self.slot != slot
            || self.lane != lane
            || self.batch_digest != batch_digest
            || self.source_digest != source_digest
            || !is_digest(&self.source_digest)
            || self.state_generation == 0
            || !(1..=MAX_FRAMES).contains(&self.frame_count)
            || self.input_count == 0
            || self.input_count > 1_000_000
            || self.stdout_digest == [0; 32]
            || self.stderr_digest == [0; 32]
            || self.persistence_digest == [0; 32]
        {
            return Err("resident MPC receipt differs from its sealed execution".into());
        }
        let expected_name = format!("Transactions-P{node}.data");
        if self
            .persistence_path
            .file_name()
            .and_then(|name| name.to_str())
            != Some(expected_name.as_str())
        {
            return Err("resident MPC receipt names another party's persistence file".into());
        }
        Ok(())
    }

    /// Stable public commitment to the exact node-local MP-SPDZ execution and
    /// proof handoff.  It contains no path, price, quantity, policy, inventory,
    /// reserve opening, or Shamir share.
    pub fn public_digest(&self) -> Result<[u8; 32], String> {
        let source: [u8; 32] = hex::decode(&self.source_digest)
            .map_err(|_| "resident MPC source digest is malformed".to_string())?
            .try_into()
            .map_err(|_| "resident MPC source digest is malformed".to_string())?;
        let mut hash = Sha256::new();
        hash.update(EXECUTION_RECEIPT_DOMAIN);
        hash.update(self.node.to_be_bytes());
        hash.update(self.slot.to_be_bytes());
        hash.update((self.lane as u64).to_be_bytes());
        hash.update(self.batch_digest);
        hash.update(source);
        hash.update(self.state_generation.to_be_bytes());
        hash.update((self.frame_count as u64).to_be_bytes());
        hash.update((self.input_count as u64).to_be_bytes());
        hash.update(self.stdout_digest);
        hash.update(self.stderr_digest);
        hash.update(self.persistence_digest);
        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_rfq_taker_reserves_precede_standing_maker_reserves() {
        let request = (0_u64..REQUEST_VALUES as u64)
            .map(FieldElement::from_u64)
            .collect::<Vec<_>>();
        let state = MpcSecretState {
            version: 1,
            node: 0,
            generation: 1,
            source_sha256: "00".repeat(32),
            dvp_input_shares: (100..105).map(|value| value.to_string()).collect(),
            policy_input_shares: (200..210).map(|value| value.to_string()).collect(),
            quote_policy_blinding_input_shares: Vec::new(),
        };
        let assembled = assemble_party_input(&request, &state, 1).unwrap();
        let expected = [
            0, 1, 2, 3, 4, 5, // request prefix
            10, 11, 12, 13, // per-RFQ Taker reserve rails
            100, 101, 102, 103, 104, // standing Maker reserve rails and handle
            6, 7, 8, 9, // Taker limit and commitment fields
            200, 201, 202, 203, 204, 205, 206, 207, 208, 209, // Maker policy
        ]
        .map(|value| value.to_string())
        .to_vec();
        assert_eq!(assembled, expected);
    }

    #[test]
    fn public_execution_receipt_excludes_local_path_but_binds_persistence() {
        let receipt = ResidentExecutionReceipt {
            node: 2,
            slot: 9,
            lane: 1,
            batch_digest: [3; 32],
            source_digest: "04".repeat(32),
            state_generation: 1,
            frame_count: 7,
            input_count: 32,
            elapsed_ns: 99,
            stdout_digest: [5; 32],
            stderr_digest: [6; 32],
            persistence_path: PathBuf::from("/private/a/Transactions-P2.data"),
            persistence_digest: [7; 32],
        };
        receipt
            .validate_against(2, 9, 1, [3; 32], &"04".repeat(32))
            .unwrap();
        let digest = receipt.public_digest().unwrap();
        let mut moved = receipt.clone();
        moved.persistence_path = PathBuf::from("/private/b/Transactions-P2.data");
        assert_eq!(moved.public_digest().unwrap(), digest);
        moved.persistence_digest[0] ^= 1;
        assert_ne!(moved.public_digest().unwrap(), digest);
    }
}
