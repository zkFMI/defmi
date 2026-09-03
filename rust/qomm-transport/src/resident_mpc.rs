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
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use qomm_mpc::inputs::DvpInputs;
use qomm_mpc::persistence::{
    read_local_dvp_handoff_from_quote, FieldElement as DecimalFieldElement,
};
use qomm_mpc::program::ed25519_lagrange_at_zero;
use qomm_zk::pedersen::Pedersen;
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
    /// Which canonical DeFMI standing pool each Maker reserve slot mirrors.
    /// The coordinator compares these against DeFMI before every execution;
    /// a slot without a binding is either padding or not yet registered.
    #[serde(default)]
    pub standing_pool_bindings: Vec<StandingPoolBinding>,
}

/// The DeFMI standing pool one Maker slot of the resident state currently
/// mirrors. `pool_sequence` is the canonical pool sequence whose remainder
/// opening this node's shares (together with the other nodes') reconstruct.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StandingPoolBinding {
    pub maker: usize,
    /// `0`: securities pool used when the Taker buys; `1`: cash pool used when
    /// the Taker sells.  This is the circuit's rail order, not a trade side.
    pub direction: u8,
    #[serde(with = "hex32")]
    pub pool_id: [u8; 32],
    pub pool_sequence: u64,
}

/// How the compiled circuit combines the seven party inputs of one secret.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSharing {
    /// `secret_input()` multiplies party `p`'s input by its Lagrange
    /// coefficient, so the state stores raw Shamir evaluations.
    Shamir,
    /// `secret_input()` sums the party inputs, so the state stores each Shamir
    /// evaluation already scaled by the node's Lagrange coefficient. Summing the
    /// seven stored values reconstructs the secret exactly as the Lagrange
    /// circuit would, without any node learning more than its own share.
    Additive,
}

impl MpcSecretState {
    pub fn verify(&self, node: u16, source_sha256: &str, n_mm: usize) -> Result<(), String> {
        // Maker policies are either resident (ten shares per padded Maker, as
        // in the WAN deployment) or delivered per RFQ as mandate-bound inputs
        // (the Docker demo). The blinding vector may only exist alongside
        // resident policies.
        let resident_policies = !self.policy_input_shares.is_empty();
        if self.version != 1
            || self.node != node
            || self.source_sha256 != source_sha256
            || !is_digest(&self.source_sha256)
            || self.dvp_input_shares.len() != DvpInputs::standing_value_count(n_mm)
            || (resident_policies
                && self.policy_input_shares.len() != n_mm.saturating_mul(POLICY_FIELDS))
            || (!resident_policies && !self.quote_policy_blinding_input_shares.is_empty())
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
        let mut seen = std::collections::BTreeSet::new();
        for binding in &self.standing_pool_bindings {
            if binding.maker >= n_mm
                || binding.direction > 1
                || binding.pool_id == [0; 32]
                || !seen.insert((binding.maker, binding.direction))
            {
                return Err(
                    "encrypted MPC state names an invalid or duplicate standing pool".into(),
                );
            }
        }
        Ok(())
    }

    /// True when every Maker policy is a resident share rather than a per-RFQ
    /// input.  The WAN runner requires this; the Docker demo does not use it.
    pub fn has_resident_policies(&self) -> bool {
        !self.policy_input_shares.is_empty()
    }

    /// Index of the amount share for one Maker rail inside `dvp_input_shares`.
    /// The blinding share follows it immediately.
    pub fn standing_share_offset(maker: usize, direction: u8) -> Result<usize, String> {
        if direction > 1 {
            return Err("standing pool direction is outside its rail bound".into());
        }
        maker
            .checked_mul(5)
            .and_then(|value| value.checked_add(usize::from(direction) * 2))
            .ok_or_else(|| "standing-pool MPC state offset overflowed".to_string())
    }

    pub fn standing_pool_binding(
        &self,
        maker: usize,
        direction: u8,
    ) -> Option<&StandingPoolBinding> {
        self.standing_pool_bindings
            .iter()
            .find(|binding| binding.maker == maker && binding.direction == direction)
    }

    /// Pedersen commitment to this node's stored (amount, blinding) share pair
    /// for one Maker rail under the DeFMI settlement key.  Combining the seven
    /// nodes' values with [`combine_partial_commitments`] yields the commitment
    /// of the reconstructed opening, so the coordinator can audit that the
    /// resident state still equals the canonical DeFMI pool note without any
    /// node revealing its share or the coordinator learning the opening.
    pub fn standing_pool_partial_commitment(
        &self,
        maker: usize,
        direction: u8,
    ) -> Result<[u8; 32], String> {
        let offset = Self::standing_share_offset(maker, direction)?;
        let amount = self
            .dvp_input_shares
            .get(offset)
            .ok_or_else(|| "standing-pool amount share is outside node state".to_string())?;
        let blinding = self
            .dvp_input_shares
            .get(offset + 1)
            .ok_or_else(|| "standing-pool blinding share is outside node state".to_string())?;
        Ok(Pedersen::new(b"qomm:defmi:v1")
            .commit(&decimal_to_scalar(amount)?, &decimal_to_scalar(blinding)?)
            .compress()
            .to_bytes())
    }

    fn set_standing_pool_binding(&mut self, binding: StandingPoolBinding) {
        match self.standing_pool_bindings.iter_mut().find(|existing| {
            existing.maker == binding.maker && existing.direction == binding.direction
        }) {
            Some(existing) => *existing = binding,
            None => self.standing_pool_bindings.push(binding),
        }
        self.standing_pool_bindings
            .sort_by_key(|binding| (binding.maker, binding.direction));
    }
}

/// Lagrange coefficient at zero for MP-SPDZ party `node`, whose Shamir
/// evaluation point is `node + 1`.  This is the same convention the proof
/// parties use (`party = node + 1`) when they combine range-proof shares.
pub fn node_lagrange_coefficient(node: u16, n_parties: u16) -> Result<Scalar, String> {
    let coefficients =
        ed25519_lagrange_at_zero(usize::from(n_parties)).map_err(|error| error.to_string())?;
    coefficients
        .get(usize::from(node))
        .map(|value| decimal_to_scalar(value))
        .ok_or_else(|| "MPC node index is outside the Lagrange coefficient table".to_string())?
}

/// Parse a canonical decimal field element (optionally negative) into the
/// Ed25519 scalar field, which is the MP-SPDZ prime used by every QOMM circuit.
pub fn decimal_to_scalar(value: &str) -> Result<Scalar, String> {
    if !is_decimal(value) {
        return Err("field element is not a canonical decimal".into());
    }
    let (negative, digits) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let mut limbs = [0_u64; 8];
    for digit in digits.bytes() {
        let mut carry = u128::from(digit - b'0');
        for limb in limbs.iter_mut() {
            let wide = u128::from(*limb) * 10 + carry;
            *limb = wide as u64;
            carry = wide >> 64;
        }
        if carry != 0 {
            return Err("field element exceeds 512 bits".into());
        }
    }
    let mut bytes = [0_u8; 64];
    for (index, limb) in limbs.iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
    Ok(if negative { -scalar } else { scalar })
}

/// Canonical (reduced, non-negative) decimal rendering of a scalar.
pub fn scalar_to_decimal(value: &Scalar) -> String {
    DecimalFieldElement::from_bytes_le(&value.to_bytes()).to_string()
}

/// Convert one Shamir evaluation read from this node's MP-SPDZ persistence
/// into the value the resident state must store for the configured circuit.
pub fn resident_share_from_evaluation(
    node: u16,
    n_parties: u16,
    sharing: InputSharing,
    evaluation: &DecimalFieldElement,
) -> Result<String, String> {
    let evaluation = decimal_to_scalar(&evaluation.to_string())?;
    Ok(match sharing {
        InputSharing::Shamir => scalar_to_decimal(&evaluation),
        InputSharing::Additive => {
            scalar_to_decimal(&(node_lagrange_coefficient(node, n_parties)? * evaluation))
        }
    })
}

/// Combine the seven nodes' partial commitments of one Maker rail into the
/// commitment of the reconstructed opening.
pub fn combine_partial_commitments(
    partials: &[[u8; 32]],
    sharing: InputSharing,
    n_parties: u16,
) -> Result<[u8; 32], String> {
    if partials.len() != usize::from(n_parties) {
        return Err("partial commitment set does not cover every MPC node".into());
    }
    let mut total = RistrettoPoint::identity();
    for (node, partial) in partials.iter().enumerate() {
        let point = CompressedRistretto(*partial).decompress().ok_or_else(|| {
            format!("MPC node {node} returned a non-canonical partial commitment")
        })?;
        total += match sharing {
            InputSharing::Additive => point,
            InputSharing::Shamir => {
                point
                    * node_lagrange_coefficient(
                        u16::try_from(node).map_err(|_| "node index exceeds u16")?,
                        n_parties,
                    )?
            }
        };
    }
    Ok(total.compress().to_bytes())
}

/// Offset of the standing Maker segment inside one party input file: six
/// public/admission values, then the four per-RFQ Taker reserve values.  This
/// is the order `qomm_mpc::inputs::build_inputs` deals and the circuit reads.
pub const STANDING_SHARES_OFFSET: usize = REQUEST_PUBLIC_AND_ADMISSION_VALUES + 4;

/// Replace the standing Maker segment of a coordinator-dealt party input with
/// this node's resident shares.  The coordinator's copy of that segment is
/// ignored, so a restarted coordinator cannot re-inject an initial balance.
pub fn splice_standing_maker_shares(
    inputs: &mut [String],
    state: &MpcSecretState,
    n_mm: usize,
) -> Result<(), String> {
    let count = DvpInputs::standing_value_count(n_mm);
    if state.dvp_input_shares.len() != count {
        return Err("resident Maker state does not match the circuit's Maker population".into());
    }
    let segment = inputs
        .get_mut(STANDING_SHARES_OFFSET..STANDING_SHARES_OFFSET + count)
        .ok_or_else(|| "party input is shorter than its standing Maker segment".to_string())?;
    for (slot, share) in segment.iter_mut().zip(&state.dvp_input_shares) {
        *slot = share.clone();
    }
    Ok(())
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
        self.load_unlocked()
    }

    /// Whether a state file exists at all.  A node without one has never been
    /// seeded; it must refuse to execute rather than invent Maker inputs.
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    fn load_unlocked(&self) -> Result<MpcSecretState, String> {
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
        let mut clear = decrypt_authenticated(
            &derive_secret_key(&self.passphrase, salt)?,
            nonce,
            STATE_AAD,
            &raw[nonce_start + NONCE_BYTES..],
        )?;
        let decoded = serde_json::from_slice(&clear)
            .map_err(|_| "MPC-state authentication succeeded but its payload is malformed".into());
        clear.fill(0);
        decoded
    }

    /// Atomically replace one node's secret-share state after an accepted
    /// DeFMI transition. The expected generation is a compare-and-swap guard:
    /// two RFQs proved against the same parent state cannot both advance it.
    pub fn compare_and_swap(
        &self,
        expected_generation: u64,
        next: &MpcSecretState,
    ) -> Result<(), String> {
        let _lock = FileLock::acquire(&self.path)?;
        let current = self.load_unlocked()?;
        if current.generation != expected_generation {
            return Err("MPC secret-state generation changed before commit".into());
        }
        if next.generation
            != expected_generation
                .checked_add(1)
                .ok_or_else(|| "MPC secret-state generation overflowed before commit".to_string())?
            || next.version != current.version
            || next.node != current.node
            || next.source_sha256 != current.source_sha256
            || next.dvp_input_shares.len() != current.dvp_input_shares.len()
            || next.policy_input_shares != current.policy_input_shares
            || next.quote_policy_blinding_input_shares != current.quote_policy_blinding_input_shares
        {
            return Err("MPC secret-state update changed its circuit, identity, or policy".into());
        }
        self.write_unlocked(next)
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StandingPoolStateReceipt {
    pub node: u16,
    pub maker: usize,
    pub direction: u8,
    pub before_generation: u64,
    pub after_generation: u64,
    #[serde(with = "hex32")]
    pub proof_job_id: [u8; 32],
    #[serde(with = "hex32")]
    pub allocation_statement: [u8; 32],
    #[serde(with = "hex32")]
    pub persistence_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub receipt_digest: [u8; 32],
}

impl StandingPoolStateReceipt {
    fn unsigned_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"QOMM:MPC:STANDING-POOL-STATE-RECEIPT:v1");
        hash.update(self.node.to_be_bytes());
        hash.update((self.maker as u64).to_be_bytes());
        hash.update([self.direction]);
        hash.update(self.before_generation.to_be_bytes());
        hash.update(self.after_generation.to_be_bytes());
        hash.update(self.proof_job_id);
        hash.update(self.allocation_statement);
        hash.update(self.persistence_digest);
        hash.finalize().into()
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.direction > 1
            || self.before_generation == 0
            || self.after_generation != self.before_generation.saturating_add(1)
            || self.proof_job_id == [0; 32]
            || self.allocation_statement == [0; 32]
            || self.persistence_digest == [0; 32]
            || self.receipt_digest != self.unsigned_digest()
        {
            return Err("standing-pool MPC state receipt is incomplete".into());
        }
        Ok(())
    }
}

/// Commit the selected Maker parent-pool remainder into one node's encrypted
/// long-lived MPC state. `direction=0` updates the securities pool used when
/// the Taker buys; `direction=1` updates the cash pool used when the Taker
/// sells. The clear remainder is never reconstructed here or returned.
///
/// This is the WAN-runner entry point: the resident circuit reconstructs its
/// inputs with Lagrange coefficients, so raw Shamir evaluations are stored and
/// the pool binding is tracked by the deployment manifest instead.
#[allow(clippy::too_many_arguments)]
pub fn commit_standing_pool_remainder(
    config: &ResidentMpcConfig,
    persistence_path: &Path,
    maker: usize,
    direction: u8,
    expected_generation: u64,
    proof_job_id: [u8; 32],
    allocation_statement: [u8; 32],
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    eligibility_bits: usize,
    span_bits: usize,
) -> Result<StandingPoolStateReceipt, String> {
    let mut passphrase = read_private_secret(&config.passphrase_file)?;
    let store = EncryptedMpcStateStore::new(&config.state_store, &passphrase)?;
    passphrase.fill(0);
    commit_standing_pool_remainder_with_store(StandingPoolCommitRequest {
        store: &store,
        node: config.node,
        n_parties: config.n_parties,
        n_mm: config.n_mm,
        source_sha256: &config.source_sha256,
        sharing: InputSharing::Shamir,
        persistence_path,
        maker,
        direction,
        expected_generation,
        proof_job_id,
        allocation_statement,
        binding: None,
        amount_bits,
        price_bits,
        remainder_bits,
        eligibility_bits,
        span_bits,
    })
}

/// One node-local standing-pool commit.  Every field is public or node-local;
/// the only secret material involved is the node's own persistence file and
/// its own encrypted state.
pub struct StandingPoolCommitRequest<'a> {
    pub store: &'a EncryptedMpcStateStore,
    pub node: u16,
    pub n_parties: u16,
    pub n_mm: usize,
    pub source_sha256: &'a str,
    pub sharing: InputSharing,
    pub persistence_path: &'a Path,
    pub maker: usize,
    pub direction: u8,
    /// Compare-and-swap guard: the state generation the accepted execution
    /// was proved against.
    pub expected_generation: u64,
    pub proof_job_id: [u8; 32],
    /// Canonical DeFMI identifier of the accepted allocation.  The Docker demo
    /// passes the remainder note id, which binds the proof job and the new pool
    /// commitment and is readable from canonical DeFMI after any outage.
    pub allocation_statement: [u8; 32],
    /// Pool the committed remainder now mirrors.  `None` leaves the slot's
    /// binding untouched for deployments that track pools elsewhere.
    pub binding: Option<StandingPoolBinding>,
    pub amount_bits: usize,
    pub price_bits: usize,
    pub remainder_bits: usize,
    pub eligibility_bits: usize,
    pub span_bits: usize,
}

pub fn commit_standing_pool_remainder_with_store(
    request: StandingPoolCommitRequest<'_>,
) -> Result<StandingPoolStateReceipt, String> {
    let StandingPoolCommitRequest {
        store,
        node,
        n_parties,
        n_mm,
        source_sha256,
        sharing,
        persistence_path,
        maker,
        direction,
        expected_generation,
        proof_job_id,
        allocation_statement,
        binding,
        amount_bits,
        price_bits,
        remainder_bits,
        eligibility_bits,
        span_bits,
    } = request;
    if maker >= n_mm
        || direction > 1
        || expected_generation == 0
        || proof_job_id == [0; 32]
        || allocation_statement == [0; 32]
        || binding.as_ref().is_some_and(|binding| {
            binding.maker != maker || binding.direction != direction || binding.pool_id == [0; 32]
        })
    {
        return Err("standing-pool MPC state commit is outside its bound".into());
    }
    protected_persistence(persistence_path)?;
    let persistence_digest: [u8; 32] =
        Sha256::digest(fs::read(persistence_path).map_err(|error| error.to_string())?).into();
    let handoff = read_local_dvp_handoff_from_quote(
        persistence_path,
        usize::from(node),
        n_mm,
        amount_bits,
        price_bits,
        remainder_bits,
        eligibility_bits,
        span_bits,
        -1,
    )
    .map_err(|error| error.to_string())?;
    if handoff.party != usize::from(node) {
        return Err("standing-pool handoff belongs to another MPC node".into());
    }
    let mut next = store.load()?;
    next.verify(node, source_sha256, n_mm)?;
    if next.generation != expected_generation {
        return Err("standing-pool commit was proved from a stale MPC generation".into());
    }
    let offset = MpcSecretState::standing_share_offset(maker, direction)?;
    let amount = resident_share_from_evaluation(
        node,
        n_parties,
        sharing,
        &handoff.maker_pool_remainder.value_share,
    )?;
    let blinding = resident_share_from_evaluation(
        node,
        n_parties,
        sharing,
        &handoff.maker_pool_remainder.blinding_share,
    )?;
    *next
        .dvp_input_shares
        .get_mut(offset)
        .ok_or_else(|| "standing-pool amount share is outside node state".to_string())? = amount;
    *next
        .dvp_input_shares
        .get_mut(offset + 1)
        .ok_or_else(|| "standing-pool blinding share is outside node state".to_string())? =
        blinding;
    if let Some(binding) = binding {
        next.set_standing_pool_binding(binding);
    }
    next.generation = expected_generation
        .checked_add(1)
        .ok_or_else(|| "standing-pool MPC generation overflowed".to_string())?;
    store.compare_and_swap(expected_generation, &next)?;
    let mut receipt = StandingPoolStateReceipt {
        node,
        maker,
        direction,
        before_generation: expected_generation,
        after_generation: next.generation,
        proof_job_id,
        allocation_statement,
        persistence_digest,
        receipt_digest: [0; 32],
    };
    receipt.receipt_digest = receipt.unsigned_digest();
    receipt.verify()?;
    Ok(receipt)
}

/// Point one Maker rail of the resident state at a freshly registered DeFMI
/// pool whose opening the registering party dealt.  This is the only path
/// that replaces a slot with coordinator-supplied shares, and it is limited to
/// pools at sequence zero: a pool that has already been allocated from can
/// only be reached through [`commit_standing_pool_remainder_with_store`].
#[allow(clippy::too_many_arguments)]
pub fn rebind_standing_pool(
    store: &EncryptedMpcStateStore,
    node: u16,
    n_mm: usize,
    source_sha256: &str,
    expected_generation: u64,
    binding: StandingPoolBinding,
    amount_share: &str,
    blinding_share: &str,
) -> Result<MpcSecretState, String> {
    if binding.maker >= n_mm
        || binding.direction > 1
        || binding.pool_id == [0; 32]
        || binding.pool_sequence != 0
        || expected_generation == 0
        || !is_decimal(amount_share)
        || !is_decimal(blinding_share)
    {
        return Err("standing-pool rebind is outside its bound".into());
    }
    let mut next = store.load()?;
    next.verify(node, source_sha256, n_mm)?;
    if next.generation != expected_generation {
        return Err("standing-pool rebind was prepared from a stale MPC generation".into());
    }
    let offset = MpcSecretState::standing_share_offset(binding.maker, binding.direction)?;
    *next
        .dvp_input_shares
        .get_mut(offset)
        .ok_or_else(|| "standing-pool amount share is outside node state".to_string())? =
        amount_share.to_string();
    *next
        .dvp_input_shares
        .get_mut(offset + 1)
        .ok_or_else(|| "standing-pool blinding share is outside node state".to_string())? =
        blinding_share.to_string();
    next.set_standing_pool_binding(binding);
    next.generation = expected_generation
        .checked_add(1)
        .ok_or_else(|| "standing-pool MPC generation overflowed".to_string())?;
    store.compare_and_swap(expected_generation, &next)?;
    Ok(next)
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
    let mut passphrase = read_private_secret(&config.passphrase_file)?;
    let state_store = EncryptedMpcStateStore::new(&config.state_store, &passphrase)?;
    passphrase.fill(0);
    let state = state_store.load()?;
    state.verify(config.node, source_digest, config.n_mm)?;
    if !state.has_resident_policies() {
        return Err("resident WAN execution requires resident Maker policy shares".into());
    }
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
            standing_pool_bindings: Vec::new(),
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
    fn secret_state_compare_and_swap_rejects_a_second_same_generation_rfq() {
        let root = tempfile::tempdir().unwrap();
        let store =
            EncryptedMpcStateStore::new(root.path().join("state.qms"), b"test-passphrase").unwrap();
        let initial = MpcSecretState {
            version: 1,
            node: 0,
            generation: 7,
            source_sha256: "11".repeat(32),
            dvp_input_shares: (100..105).map(|value| value.to_string()).collect(),
            policy_input_shares: (200..210).map(|value| value.to_string()).collect(),
            quote_policy_blinding_input_shares: (300..309).map(|value| value.to_string()).collect(),
            standing_pool_bindings: Vec::new(),
        };
        store.initialize(&initial).unwrap();
        let mut winner = initial.clone();
        winner.generation = 8;
        winner.dvp_input_shares[0] = "91".into();
        winner.dvp_input_shares[1] = "92".into();
        store.compare_and_swap(7, &winner).unwrap();
        assert_eq!(store.load().unwrap(), winner);

        let mut stale = initial.clone();
        stale.generation = 8;
        stale.dvp_input_shares[0] = "81".into();
        assert_eq!(
            store.compare_and_swap(7, &stale),
            Err("MPC secret-state generation changed before commit".into())
        );
        assert_eq!(store.load().unwrap(), winner);
    }

    #[test]
    fn additive_resident_shares_reconstruct_a_shamir_dealt_secret() {
        // Degree-two polynomial through the secret, evaluated at the MP-SPDZ
        // party points 1..=7.  The additive form must sum to the secret and the
        // Shamir form must combine to it through the coefficient table.
        let secret = Scalar::from(4_900_u64);
        let (a1, a2) = (Scalar::from(31_u64), Scalar::from(77_u64));
        let evaluations = (1..=7_u64)
            .map(|x| {
                let x = Scalar::from(x);
                secret + a1 * x + a2 * x * x
            })
            .collect::<Vec<_>>();
        let mut additive_sum = Scalar::ZERO;
        let mut shamir_sum = Scalar::ZERO;
        for (node, evaluation) in evaluations.iter().enumerate() {
            let element = DecimalFieldElement::from_bytes_le(&evaluation.to_bytes());
            let additive =
                resident_share_from_evaluation(node as u16, 7, InputSharing::Additive, &element)
                    .unwrap();
            let shamir =
                resident_share_from_evaluation(node as u16, 7, InputSharing::Shamir, &element)
                    .unwrap();
            assert!(is_decimal(&additive) && is_decimal(&shamir));
            additive_sum += decimal_to_scalar(&additive).unwrap();
            shamir_sum += node_lagrange_coefficient(node as u16, 7).unwrap()
                * decimal_to_scalar(&shamir).unwrap();
        }
        assert_eq!(additive_sum, secret);
        assert_eq!(shamir_sum, secret);
        assert_eq!(decimal_to_scalar("-1").unwrap(), -Scalar::ONE);
        assert_eq!(scalar_to_decimal(&Scalar::from(10_u64)), "10");
    }

    #[test]
    fn partial_commitments_combine_to_the_reconstructed_opening() {
        let key = Pedersen::new(b"qomm:defmi:v1");
        let value = Scalar::from(4_900_u64);
        let blinding = Scalar::from(123_456_789_u64);
        let mut value_shares = (0..6)
            .map(|i| Scalar::from(1_000 + i as u64))
            .collect::<Vec<_>>();
        let mut blinding_shares = (0..6)
            .map(|i| Scalar::from(2_000 + i as u64))
            .collect::<Vec<_>>();
        value_shares.push(value - value_shares.iter().sum::<Scalar>());
        blinding_shares.push(blinding - blinding_shares.iter().sum::<Scalar>());
        let partials = value_shares
            .iter()
            .zip(&blinding_shares)
            .enumerate()
            .map(|(node, (v, r))| {
                let mut shares = vec!["0".to_string(); 10];
                shares[5] = scalar_to_decimal(v);
                shares[6] = scalar_to_decimal(r);
                let state = MpcSecretState {
                    version: 1,
                    node: node as u16,
                    generation: 1,
                    source_sha256: "22".repeat(32),
                    dvp_input_shares: shares,
                    policy_input_shares: Vec::new(),
                    quote_policy_blinding_input_shares: Vec::new(),
                    standing_pool_bindings: vec![StandingPoolBinding {
                        maker: 1,
                        direction: 0,
                        pool_id: [9; 32],
                        pool_sequence: 3,
                    }],
                };
                state.verify(node as u16, &"22".repeat(32), 2).unwrap();
                state.standing_pool_partial_commitment(1, 0).unwrap()
            })
            .collect::<Vec<_>>();
        let combined = combine_partial_commitments(&partials, InputSharing::Additive, 7).unwrap();
        assert_eq!(
            combined,
            key.commit(&value, &blinding).compress().to_bytes()
        );
        assert!(combine_partial_commitments(&partials[..6], InputSharing::Additive, 7).is_err());
    }

    #[test]
    fn splice_replaces_only_the_standing_maker_segment() {
        let n_mm = 2;
        let mut inputs = (0..40).map(|value| value.to_string()).collect::<Vec<_>>();
        let state = MpcSecretState {
            version: 1,
            node: 3,
            generation: 4,
            source_sha256: "33".repeat(32),
            dvp_input_shares: (500..510).map(|value| value.to_string()).collect(),
            policy_input_shares: Vec::new(),
            quote_policy_blinding_input_shares: Vec::new(),
            standing_pool_bindings: Vec::new(),
        };
        splice_standing_maker_shares(&mut inputs, &state, n_mm).unwrap();
        for (index, value) in inputs.iter().enumerate() {
            let expected = if (STANDING_SHARES_OFFSET..STANDING_SHARES_OFFSET + 10).contains(&index)
            {
                (500 + index - STANDING_SHARES_OFFSET).to_string()
            } else {
                index.to_string()
            };
            assert_eq!(*value, expected, "index {index}");
        }
        assert!(splice_standing_maker_shares(&mut inputs[..12], &state, n_mm).is_err());
    }

    #[test]
    fn rebind_is_limited_to_fresh_pools_and_advances_the_generation() {
        let root = tempfile::tempdir().unwrap();
        let store =
            EncryptedMpcStateStore::new(root.path().join("state.qms"), b"test-passphrase").unwrap();
        assert!(!store.exists());
        let source = "44".repeat(32);
        store
            .initialize(&MpcSecretState {
                version: 1,
                node: 2,
                generation: 1,
                source_sha256: source.clone(),
                dvp_input_shares: vec!["0".into(); 5],
                policy_input_shares: Vec::new(),
                quote_policy_blinding_input_shares: Vec::new(),
                standing_pool_bindings: Vec::new(),
            })
            .unwrap();
        assert!(store.exists());
        let binding = StandingPoolBinding {
            maker: 0,
            direction: 1,
            pool_id: [7; 32],
            pool_sequence: 0,
        };
        let next =
            rebind_standing_pool(&store, 2, 1, &source, 1, binding.clone(), "12", "34").unwrap();
        assert_eq!(next.generation, 2);
        assert_eq!(next.dvp_input_shares, vec!["0", "0", "12", "34", "0"]);
        assert_eq!(next.standing_pool_binding(0, 1), Some(&binding));
        assert_eq!(store.load().unwrap(), next);
        let mut consumed = binding.clone();
        consumed.pool_sequence = 1;
        assert!(rebind_standing_pool(&store, 2, 1, &source, 2, consumed, "1", "2").is_err());
        assert!(rebind_standing_pool(&store, 2, 1, &source, 1, binding, "1", "2").is_err());
        // Legacy state files without bindings still load.
        let legacy: MpcSecretState = serde_json::from_str(
            r#"{"version":1,"node":2,"generation":1,"source_sha256":"00","dvp_input_shares":[],"policy_input_shares":[]}"#,
        )
        .unwrap();
        assert!(legacy.standing_pool_bindings.is_empty());
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
