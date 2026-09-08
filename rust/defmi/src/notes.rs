//! Balances that do not sit at an address.
//!
//! A holding is a note `C = g^S · A_a^v · h^r`. The recipient, not the sender,
//! controls the serial: an address is `(A, B) = (g^a, g^b)`, a sender draws an
//! ephemeral `e`, publishes `E = g^e`, and builds against `g^{H(A^e)}·B`. That
//! point is computable from public data but `S = H(A^e) + b` is not, so a
//! sender can address a note it cannot spend.
//!
//! Version 2 uses the pinned upstream parallel Triptych/RingCT proof. It binds
//! ownership and value at the SAME hidden ring position and publishes `U/S`,
//! not the note's public owner key `g^S`. Conservation is a fixed-zero proof.
//! V1 wire is rejected; a live V1 ledger requires an explicit reviewed migration.

use crate::note_membership;
pub use crate::note_membership::NoteMembershipProof;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::{collections::HashSet, sync::Arc};
use zkfmi_crypto::{
    hybrid::kem::HybridKemKey,
    sealed::{SealedMessage, SealingPurpose, RECIPIENT_PUBLIC_BYTES},
    traits::KemDecapsulator,
};
use zkfmi_crypto::{hybrid::signature::HybridVerifier, key::KeyPurpose, traits::Verifier};
use zkfmi_zk::pedersen::Pedersen;
use zkfmi_zk::sigma::{prove_zero_opening, verify_zero_opening, OpeningProof};
pub use zkpi_committee::standing_pool::NoteOpening;

fn scalar_from(label: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"qomm:defmi:note:v1:");
    hasher.update(label);
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

#[derive(Clone, Copy)]
pub struct Address {
    pub view: RistrettoPoint,
    pub spend: RistrettoPoint,
    /// Independently generated hybrid recipient key; never derived from a curve scalar.
    pub opening_public: [u8; RECIPIENT_PUBLIC_BYTES],
}

/// The two secrets behind an address, split because they do different jobs: the
/// view key finds your own notes and could be handed to an auditor, while only
/// the spend key turns a note into a serial number.
pub struct Wallet {
    view: Scalar,
    spend: Scalar,
    opening_key: Arc<HybridKemKey>,
    pub address: Address,
}

impl Wallet {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let view = Scalar::random(rng);
        let spend = Scalar::random(rng);
        let mut seed = zeroize::Zeroizing::new([0; 96]);
        rng.fill_bytes(seed.as_mut());
        Self::from_parts(view, spend, HybridKemKey::from_seed(&seed))
    }

    /// Restore every independent secret. A missing recipient key is never
    /// replaced by one derived from the view or spend scalar.
    pub fn from_parts(
        view: Scalar,
        spend: Scalar,
        opening_key: impl Into<Arc<HybridKemKey>>,
    ) -> Self {
        let opening_key = opening_key.into();
        let opening_public = opening_key
            .public_key()
            .try_into()
            .expect("fixed hybrid public key");
        Wallet {
            view,
            spend,
            opening_key,
            address: Address {
                view: G * view,
                spend: G * spend,
                opening_public,
            },
        }
    }

    pub fn opening_key(&self) -> &HybridKemKey {
        &self.opening_key
    }

    /// The half that finds notes and cannot move them.
    pub fn view_key(&self) -> ViewKey {
        ViewKey {
            scalar: self.view,
            opening_key: Arc::clone(&self.opening_key),
        }
    }
    fn shared(&self, ephemeral: &RistrettoPoint) -> Scalar {
        scalar_from(b"shared", &[(ephemeral * self.view).compress().as_bytes()])
    }
    pub fn serial(&self, ephemeral: &RistrettoPoint) -> Scalar {
        self.shared(ephemeral) + self.spend
    }
}

/// Enough to find notes addressed to one address, and not enough to spend one.
///
/// Withholding the spend key is not a policy here: the scalar a serial number
/// needs is simply not in this type, so there is no method to refuse.
#[derive(Clone)]
pub struct ViewKey {
    pub(crate) scalar: Scalar,
    opening_key: Arc<HybridKemKey>,
}

impl ViewKey {
    pub fn new(scalar: Scalar, opening_key: HybridKemKey) -> Self {
        ViewKey {
            scalar,
            opening_key: Arc::new(opening_key),
        }
    }

    pub fn opening_public(&self) -> [u8; RECIPIENT_PUBLIC_BYTES] {
        self.opening_key
            .public_key()
            .try_into()
            .expect("fixed hybrid public key")
    }

    pub fn address_view(&self) -> RistrettoPoint {
        G * self.scalar
    }

    pub(crate) fn shared(&self, ephemeral: &RistrettoPoint) -> Scalar {
        scalar_from(
            b"shared",
            &[(ephemeral * self.scalar).compress().as_bytes()],
        )
    }
}

/// What lands on the ledger. The one-time point is published separately so a
/// settlement can check that a note carries the value commitment its proof is
/// about; folded together, that check has nothing to compare.
#[derive(Clone)]
pub struct Note {
    pub one_time: RistrettoPoint,
    pub value_commitment: RistrettoPoint,
    pub ephemeral: RistrettoPoint,
    pub encrypted_opening: NoteOpening,
}

#[derive(Clone, Copy)]
pub struct Opening {
    pub value: u64,
    pub blinding: Scalar,
    pub serial: Scalar,
}

/// Stable, unlinkable linking tag. A valid secret must be nonzero; the
/// membership verifier rejects the identity produced for a zero secret.
pub fn note_nullifier(serial: &Scalar) -> RistrettoPoint {
    note_membership::nullifier(serial)
}

/// What a spend hands back: the proof that goes on the wire, the notes that go
/// into the pool, and the blindings the payer keeps.
pub struct Spend {
    pub proof: SpendProof,
    pub notes: Vec<Note>,
    /// One per output, against the asset tag the leg was proved under.
    pub tagged_blindings: Vec<Scalar>,
}

pub struct SpendProof {
    pub serial_point: RistrettoPoint,
    pub pseudo: RistrettoPoint,
    pub ring: NoteMembershipProof,
    pub outputs: Vec<RistrettoPoint>,
    pub output_notes: Vec<[u8; 32]>,
    pub output_range: RangeProof,
    pub output_range_commitments: Vec<CompressedRistretto>,
    pub balance: OpeningProof,
    pub tag: RistrettoPoint,
}

const SPEND_PROOF_WIRE_MAGIC: &[u8] = b"QOMMNSP2";
const MAX_SPEND_PROOF_WIRE: usize = 2 << 20;
const MAX_SPEND_VECTOR: usize = 64;

/// Canonical transport for a verifier-complete anonymous note spend.  The
/// wire contains only public proof material; wallet openings and long-lived
/// view/spend scalars are never serialized.
pub fn encode_spend_proof(proof: &SpendProof) -> Result<Vec<u8>, String> {
    fn push_point(out: &mut Vec<u8>, point: &RistrettoPoint) {
        out.extend_from_slice(point.compress().as_bytes());
    }
    fn push_scalar(out: &mut Vec<u8>, scalar: &Scalar) {
        out.extend_from_slice(&scalar.to_bytes());
    }
    fn push_points(out: &mut Vec<u8>, values: &[RistrettoPoint]) -> Result<(), String> {
        if values.len() > MAX_SPEND_VECTOR {
            return Err("note-spend proof point vector exceeds its bound".into());
        }
        out.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for value in values {
            push_point(out, value);
        }
        Ok(())
    }
    let mut out = Vec::new();
    out.extend_from_slice(SPEND_PROOF_WIRE_MAGIC);
    push_point(&mut out, &proof.serial_point);
    push_point(&mut out, &proof.pseudo);
    let ring = proof.ring.to_bytes();
    out.extend_from_slice(&(ring.len() as u32).to_be_bytes());
    out.extend_from_slice(&ring);
    push_points(&mut out, &proof.outputs)?;
    if proof.output_notes.len() != proof.outputs.len() {
        return Err("output note binding count mismatch".into());
    }
    out.extend_from_slice(&(proof.output_notes.len() as u32).to_be_bytes());
    for binding in &proof.output_notes {
        out.extend_from_slice(binding);
    }
    let range = proof.output_range.to_bytes();
    if range.is_empty() || range.len() > MAX_SPEND_PROOF_WIRE {
        return Err("note-spend range proof exceeds its bound".into());
    }
    out.extend_from_slice(&(range.len() as u32).to_be_bytes());
    out.extend_from_slice(&range);
    if proof.output_range_commitments.len() > MAX_SPEND_VECTOR {
        return Err("note-spend range commitments exceed their bound".into());
    }
    out.extend_from_slice(&(proof.output_range_commitments.len() as u32).to_be_bytes());
    for commitment in &proof.output_range_commitments {
        out.extend_from_slice(commitment.as_bytes());
    }
    push_point(&mut out, &proof.balance.t);
    push_scalar(&mut out, &proof.balance.z_value);
    push_scalar(&mut out, &proof.balance.z_blinding);
    push_point(&mut out, &proof.tag);
    if out.len() > MAX_SPEND_PROOF_WIRE {
        return Err("note-spend proof wire exceeds its bound".into());
    }
    Ok(out)
}

pub fn decode_spend_proof(raw: &[u8]) -> Result<SpendProof, String> {
    struct Reader<'a> {
        raw: &'a [u8],
        at: usize,
    }
    impl<'a> Reader<'a> {
        fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
            if self.raw.len().saturating_sub(self.at) < length {
                return Err("note-spend proof wire is truncated".into());
            }
            let value = &self.raw[self.at..self.at + length];
            self.at += length;
            Ok(value)
        }
        fn count(&mut self) -> Result<usize, String> {
            let count = u32::from_be_bytes(
                self.take(4)?
                    .try_into()
                    .expect("four-byte note-spend count"),
            ) as usize;
            if count > MAX_SPEND_VECTOR {
                return Err("note-spend proof vector exceeds its bound".into());
            }
            Ok(count)
        }
        fn point(&mut self) -> Result<RistrettoPoint, String> {
            let encoded: [u8; 32] = self
                .take(32)?
                .try_into()
                .expect("thirty-two-byte Ristretto encoding");
            CompressedRistretto(encoded)
                .decompress()
                .ok_or_else(|| "note-spend proof contains a non-canonical point".into())
        }
        fn scalar(&mut self) -> Result<Scalar, String> {
            let encoded: [u8; 32] = self
                .take(32)?
                .try_into()
                .expect("thirty-two-byte scalar encoding");
            Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded))
                .ok_or_else(|| "note-spend proof contains a non-canonical scalar".into())
        }
        fn points(&mut self) -> Result<Vec<RistrettoPoint>, String> {
            let count = self.count()?;
            (0..count).map(|_| self.point()).collect()
        }
    }

    if raw.len() > MAX_SPEND_PROOF_WIRE || !raw.starts_with(SPEND_PROOF_WIRE_MAGIC) {
        return Err("note-spend proof wire has an invalid header or length".into());
    }
    let mut reader = Reader {
        raw,
        at: SPEND_PROOF_WIRE_MAGIC.len(),
    };
    let serial_point = reader.point()?;
    let pseudo = reader.point()?;
    let ring_length = u32::from_be_bytes(reader.take(4)?.try_into().unwrap()) as usize;
    let ring =
        NoteMembershipProof::from_bytes(reader.take(ring_length)?).map_err(str::to_string)?;
    let outputs = reader.points()?;
    let output_count = reader.count()?;
    if output_count != outputs.len() {
        return Err("output note binding count mismatch".into());
    }
    let output_notes = (0..output_count)
        .map(|_| Ok(reader.take(32)?.try_into().unwrap()))
        .collect::<Result<Vec<[u8; 32]>, String>>()?;
    let range_length = u32::from_be_bytes(
        reader
            .take(4)?
            .try_into()
            .expect("four-byte range-proof length"),
    ) as usize;
    if range_length == 0 || range_length > MAX_SPEND_PROOF_WIRE {
        return Err("note-spend range proof length is invalid".into());
    }
    let output_range = RangeProof::from_bytes(reader.take(range_length)?)
        .map_err(|_| "note-spend range proof is malformed".to_string())?;
    let commitment_count = reader.count()?;
    let output_range_commitments = (0..commitment_count)
        .map(|_| {
            Ok(CompressedRistretto(
                reader
                    .take(32)?
                    .try_into()
                    .expect("thirty-two-byte range commitment"),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let balance = OpeningProof {
        t: reader.point()?,
        z_value: reader.scalar()?,
        z_blinding: reader.scalar()?,
    };
    let tag = reader.point()?;
    if reader.at != raw.len() {
        return Err("note-spend proof wire has trailing bytes".into());
    }
    Ok(SpendProof {
        serial_point,
        pseudo,
        ring,
        outputs,
        output_notes,
        output_range,
        output_range_commitments,
        balance,
        tag,
    })
}

impl SpendProof {
    /// Stable identifier for the complete verifier input carried off chain.
    /// The Avalanche statement binds this digest together with the ring root,
    /// serial, lock predicate and exact output notes.  Validators trust only a
    /// k-of-n approval whose signers verified these bytes.
    pub fn digest(&self) -> [u8; 32] {
        fn point(hash: &mut sha2::Sha256, value: &RistrettoPoint) {
            hash.update(value.compress().as_bytes());
        }
        fn scalar(hash: &mut sha2::Sha256, value: &Scalar) {
            hash.update(value.to_bytes());
        }
        fn points(hash: &mut sha2::Sha256, values: &[RistrettoPoint]) {
            hash.update((values.len() as u64).to_be_bytes());
            for value in values {
                point(hash, value);
            }
        }
        let mut hash = sha2::Sha256::new();
        hash.update(b"QOMM:DEFMI:NOTE-SPEND-PROOF:v2");
        point(&mut hash, &self.serial_point);
        point(&mut hash, &self.pseudo);
        let ring = self.ring.to_bytes();
        hash.update((ring.len() as u64).to_be_bytes());
        hash.update(ring);
        points(&mut hash, &self.outputs);
        hash.update((self.output_notes.len() as u64).to_be_bytes());
        for binding in &self.output_notes {
            hash.update(binding);
        }
        let range = self.output_range.to_bytes();
        hash.update((range.len() as u64).to_be_bytes());
        hash.update(range);
        hash.update((self.output_range_commitments.len() as u64).to_be_bytes());
        for commitment in &self.output_range_commitments {
            hash.update(commitment.as_bytes());
        }
        point(&mut hash, &self.balance.t);
        scalar(&mut hash, &self.balance.z_value);
        scalar(&mut hash, &self.balance.z_blinding);
        point(&mut hash, &self.tag);
        hash.finalize().into()
    }

    pub fn matches_output_notes(&self, notes: &[Note]) -> bool {
        notes.len() == self.output_notes.len()
            && notes.len() == self.outputs.len()
            && notes.iter().zip(&self.output_notes).zip(&self.outputs).all(
                |((note, binding), commitment)| {
                    note_binding(note) == *binding && note.value_commitment == *commitment
                },
            )
    }
}

/// Hash all delivered bytes, so a proof cannot be redirected by changing only
/// the one-time destination key or its encrypted opening.
fn note_binding(note: &Note) -> [u8; 32] {
    sha2::Sha256::new()
        .chain_update(b"DEFMI:NOTE:BODY:v3")
        .chain_update(note.one_time.compress().as_bytes())
        .chain_update(note.value_commitment.compress().as_bytes())
        .chain_update(note.ephemeral.compress().as_bytes())
        .chain_update(note.encrypted_opening.binding_bytes())
        .finalize()
        .into()
}

fn opening_context(
    one_time: &RistrettoPoint,
    commitment: &RistrettoPoint,
    ephemeral: &RistrettoPoint,
) -> [u8; 32] {
    sha2::Sha256::new()
        .chain_update(b"DEFMI:NOTE:OPENING:v3")
        .chain_update(one_time.compress().as_bytes())
        .chain_update(commitment.compress().as_bytes())
        .chain_update(ephemeral.compress().as_bytes())
        .finalize()
        .into()
}

/// Ownership relation used by an existing publicly specified covenant. This
/// computes no payload opening and supplies no post-quantum anonymity guarantee.
pub fn note_serial(view: &Scalar, spend: &Scalar, ephemeral: &RistrettoPoint) -> Scalar {
    scalar_from(b"shared", &[(ephemeral * view).compress().as_bytes()]) + spend
}

pub struct NoteLedger {
    pub key: Pedersen,
    pub bits: usize,
    gens: BulletproofGens,
    pub notes: Vec<Note>,
    spent: HashSet<[u8; 32]>,
    /// The state root, kept rather than recomputed. See `snapshot`.
    rolling: sha2::Sha256,
    /// Who may create notes. `None` accepts any `add` and says so.
    issuer: Option<Vec<u8>>,
    issued: std::collections::BTreeSet<Vec<u8>>,
}

/// What an issuer signs to let one note exist.
pub fn note_issuance_body(commitment: &RistrettoPoint, nonce: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"QOMM:DEFMI:NOTE-ISSUE:v1");
    hasher.update(commitment.compress().as_bytes());
    hasher.update((nonce.len() as u64).to_be_bytes());
    hasher.update(nonce);
    hasher.finalize().to_vec()
}

impl NoteLedger {
    pub fn new(key: Pedersen, bits: usize) -> Self {
        let mut rolling = sha2::Sha256::new();
        rolling.update(b"QOMM:DEFMI:NOTES:v1");
        NoteLedger {
            gens: BulletproofGens::new(bits, 2),
            key,
            bits,
            notes: Vec::new(),
            spent: HashSet::new(),
            rolling,
            issuer: None,
            issued: std::collections::BTreeSet::new(),
        }
    }

    fn one_time_point(&self, address: &Address, shared: &Scalar) -> RistrettoPoint {
        G * shared + address.spend
    }

    /// Run by the sender. `value_commitment` lets a spend hand in a commitment
    /// already made under a blinded tag; the note still has to be openable
    /// under the bare asset generator, so `effective_blinding` is the exponent
    /// of h in that form.
    pub fn build_note<R: RngCore + CryptoRng>(
        &self,
        address: &Address,
        value: u64,
        value_commitment: RistrettoPoint,
        effective_blinding: &Scalar,
        rng: &mut R,
    ) -> Result<Note, &'static str> {
        let ephemeral_secret = Scalar::random(rng);
        let ephemeral = G * ephemeral_secret;
        let shared = scalar_from(
            b"shared",
            &[(address.view * ephemeral_secret).compress().as_bytes()],
        );
        let one_time = self.one_time_point(address, &shared);
        let context = opening_context(&one_time, &value_commitment, &ephemeral);
        let mut payload = zeroize::Zeroizing::new([0; 40]);
        payload[..8].copy_from_slice(&value.to_be_bytes());
        payload[8..].copy_from_slice(effective_blinding.as_bytes());
        let encrypted_opening = SealedMessage::seal(
            &address.opening_public,
            SealingPurpose::NoteOpening,
            &context,
            payload.as_ref(),
        )
        .map_err(|_| "note recipient encryption failed")?;
        Ok(Note {
            one_time,
            value_commitment,
            ephemeral,
            encrypted_opening: NoteOpening::Recipient(encrypted_opening),
        })
    }

    pub fn commitment_of(&self, note: &Note) -> RistrettoPoint {
        // Issuance signatures bind both components and the complete payload,
        // not a sum whose decomposition a malicious recipient can change.
        RistrettoPoint::hash_from_bytes::<Sha512>(&note_binding(note))
    }

    /// Append a note without asking where it came from.
    ///
    /// `apply_spend` uses this for the outputs of a spend, which are balanced
    /// against the note that funded them and therefore create nothing. Calling
    /// it directly is issuance, and a ledger under an issuer refuses it --- see
    /// `add_issued`.
    pub fn add(&mut self, note: Note) -> usize {
        assert!(
            self.issuer.is_none(),
            "this ledger has an issuer; use add_issued"
        );
        self.append(note)
    }

    fn append(&mut self, note: Note) -> usize {
        self.rolling
            .update(self.commitment_of(&note).compress().as_bytes());
        self.notes.push(note);
        self.notes.len() - 1
    }

    /// Append a note an issuer put its name to.
    ///
    /// The account rail got this first; the note rail had nothing, so any
    /// caller could mint a note and the pool's conservation was conservation
    /// after admission there too. Same shape: a signature over the note's
    /// commitment and a nonce, and a nonce is spent once.
    pub fn add_issued(
        &mut self,
        note: Note,
        nonce: &[u8],
        authorisation: &[u8],
    ) -> Result<usize, &'static str> {
        let issuer = self.issuer.as_ref().ok_or("this ledger has no issuer")?;
        let body = note_issuance_body(&self.commitment_of(&note), nonce);
        if self.issued.contains(&body) {
            return Err("that issuance authorisation was already used");
        }
        HybridVerifier
            .verify(KeyPurpose::Attestation, issuer, &body, authorisation)
            .map_err(|_| "the note is not signed by the issuer")?;
        self.issued.insert(body);
        Ok(self.append(note))
    }

    /// A ledger where notes can only come from one place.
    pub fn under_issuer(mut self, issuer: Vec<u8>) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Check the one-time destination before attempting authenticated decryption.
    pub fn scan(&self, wallet: &Wallet, asset_key: &Pedersen) -> Vec<(usize, Opening)> {
        self.scan_view(&wallet.view_key(), &wallet.address, asset_key)
            .into_iter()
            .map(|(index, value, blinding)| {
                (
                    index,
                    Opening {
                        value,
                        blinding,
                        serial: wallet.serial(&self.notes[index].ephemeral),
                    },
                )
            })
            .collect()
    }

    /// Incoming amounts and blindings only. The independent KEM key is part of
    /// the scoped viewing capability; a recovered curve secret alone cannot open it.
    pub fn scan_view(
        &self,
        view: &ViewKey,
        address: &Address,
        asset_key: &Pedersen,
    ) -> Vec<(usize, u64, Scalar)> {
        if view.address_view() != address.view || view.opening_public() != address.opening_public {
            return Vec::new();
        }
        self.notes
            .iter()
            .enumerate()
            .filter_map(|(index, note)| {
                let shared = view.shared(&note.ephemeral);
                if self.one_time_point(address, &shared) != note.one_time {
                    return None;
                }
                let context =
                    opening_context(&note.one_time, &note.value_commitment, &note.ephemeral);
                let NoteOpening::Recipient(envelope) = &note.encrypted_opening else {
                    return None;
                };
                let payload = envelope
                    .open(&view.opening_key, SealingPurpose::NoteOpening, &context, 40)
                    .ok()?;
                let value = u64::from_be_bytes(payload[..8].try_into().ok()?);
                if self.bits < 64 && value >= (1_u64 << self.bits) {
                    return None;
                }
                let blinding = Option::<Scalar>::from(Scalar::from_canonical_bytes(
                    payload[8..].try_into().ok()?,
                ))?;
                (asset_key.commit_u64(value, &blinding) == note.value_commitment)
                    .then_some((index, value, blinding))
            })
            .collect()
    }

    fn membership_context(
        context: &[u8],
        outputs: &[RistrettoPoint],
        notes: &[[u8; 32]],
    ) -> Vec<u8> {
        let mut hash = sha2::Sha256::new();
        hash.update(b"DEFMI:NOTE:DESTINATIONS:v2");
        hash.update((context.len() as u64).to_be_bytes());
        hash.update(context);
        hash.update((outputs.len() as u64).to_be_bytes());
        for output in outputs {
            hash.update(output.compress().as_bytes());
        }
        hash.update((notes.len() as u64).to_be_bytes());
        for note in notes {
            hash.update(note);
        }
        hash.finalize().to_vec()
    }
    fn range_transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:note:range");
        t.append_message(b"ctx", context);
        t
    }
    fn balance_transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:note:balance");
        t.append_message(b"ctx", context);
        t
    }

    fn tagged_context(context: &[u8], tag: &RistrettoPoint) -> Vec<u8> {
        let mut out = context.to_vec();
        out.extend_from_slice(b":tag:");
        out.extend_from_slice(tag.compress().as_bytes());
        out
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_spend<R: RngCore + CryptoRng>(
        &self,
        ring: &[usize],
        index: usize,
        opening: &Opening,
        tag: &RistrettoPoint,
        gamma: &Scalar,
        outputs: &[(Address, u64)],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Spend, &'static str> {
        let eligibility = vec![true; ring.len()];
        self.build_spend_constrained(
            ring,
            index,
            opening,
            tag,
            gamma,
            outputs,
            &eligibility,
            context,
            rng,
        )
    }

    /// Build a spend whose hidden input must also satisfy a public predicate.
    ///
    /// An ineligible ring member is shifted by a deterministic non-zero multiple
    /// of the base generator.  Its ordinary opening therefore no longer opens
    /// the transformed member purely against `h`; manufacturing such an opening
    /// would require the unknown discrete-log relation between `g` and `h`.
    /// This is used by reservation settlement to prove that the hidden input is
    /// the locked escrow note without publishing its position in a mixed ring.
    #[allow(clippy::too_many_arguments)]
    pub fn build_spend_constrained<R: RngCore + CryptoRng>(
        &self,
        ring: &[usize],
        index: usize,
        opening: &Opening,
        tag: &RistrettoPoint,
        gamma: &Scalar,
        outputs: &[(Address, u64)],
        eligibility: &[bool],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Spend, &'static str> {
        self.build_spend_constrained_inner(
            ring,
            index,
            opening,
            tag,
            gamma,
            outputs,
            &[],
            eligibility,
            context,
            rng,
        )
    }

    /// Build a spend with caller-selected output blindings. Reservation
    /// covenants use this to make the locked note carry the exact amount
    /// commitment already signed in the zkPI and credit-facility transition.
    /// Ordinary wallet transfers should continue using `build_spend`, which
    /// samples fresh blindings internally.
    #[allow(clippy::too_many_arguments)]
    pub fn build_spend_constrained_with_blindings<R: RngCore + CryptoRng>(
        &self,
        ring: &[usize],
        index: usize,
        opening: &Opening,
        tag: &RistrettoPoint,
        gamma: &Scalar,
        outputs: &[(Address, u64)],
        output_blindings: &[Scalar],
        eligibility: &[bool],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Spend, &'static str> {
        if output_blindings.len() != outputs.len() {
            return Err("output blindings do not match the requested outputs");
        }
        self.build_spend_constrained_inner(
            ring,
            index,
            opening,
            tag,
            gamma,
            outputs,
            output_blindings,
            eligibility,
            context,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_spend_constrained_inner<R: RngCore + CryptoRng>(
        &self,
        ring: &[usize],
        index: usize,
        opening: &Opening,
        tag: &RistrettoPoint,
        gamma: &Scalar,
        outputs: &[(Address, u64)],
        output_blindings: &[Scalar],
        eligibility: &[bool],
        context: &[u8],
        rng: &mut R,
    ) -> Result<Spend, &'static str> {
        if ring.len() != eligibility.len() || ring.iter().any(|i| *i >= self.notes.len()) {
            return Err("the constrained ring or eligibility vector is invalid");
        }
        let position = ring
            .iter()
            .position(|i| *i == index)
            .ok_or("the ring omits the note")?;
        if !eligibility[position] {
            return Err("the selected note does not satisfy the spend constraint");
        }
        let total = outputs
            .iter()
            .try_fold(0u64, |sum, (_, v)| sum.checked_add(*v))
            .ok_or("output value sum overflows")?;
        if total != opening.value {
            return Err("outputs do not sum to the note being spent");
        }
        let ctx = Self::tagged_context(context, tag);
        let tagged = self.key.with_value_generator(*tag);
        let pc = PedersenGens {
            B: *tag,
            B_blinding: self.key.h,
        };

        let serial_point = note_nullifier(&opening.serial);

        let pseudo_blinding = Scalar::random(rng);
        let pseudo = tagged.commit_u64(opening.value, &pseudo_blinding);
        let pseudo_effective = gamma * Scalar::from(opening.value) + pseudo_blinding;

        let values: Vec<u64> = outputs.iter().map(|(_, v)| *v).collect();
        let blindings: Vec<Scalar> = if output_blindings.is_empty() {
            outputs.iter().map(|_| Scalar::random(&mut *rng)).collect()
        } else {
            output_blindings.to_vec()
        };
        let (output_range, output_range_commitments) = RangeProof::prove_multiple(
            &self.gens,
            &pc,
            &mut Self::range_transcript(&ctx),
            &values,
            &blindings,
            self.bits,
        )
        .map_err(|_| "an output is not in range")?;

        let mut notes = Vec::with_capacity(outputs.len());
        let mut commitments = Vec::with_capacity(outputs.len());
        for ((address, value), blinding) in outputs.iter().zip(blindings.iter()) {
            let commitment = tagged.commit_u64(*value, blinding);
            notes.push(self.build_note(
                address,
                *value,
                commitment,
                &(gamma * Scalar::from(*value) + blinding),
                rng,
            )?);
            commitments.push(commitment);
        }
        let residual = pseudo - commitments.iter().sum::<RistrettoPoint>();
        let tagged_sum: Scalar = blindings.iter().sum();
        let balance = prove_zero_opening(
            &self.key,
            &mut Self::balance_transcript(&ctx),
            &residual,
            &(pseudo_blinding - tagged_sum),
            rng,
        );
        let output_notes = notes.iter().map(note_binding).collect::<Vec<_>>();
        let membership_context = Self::membership_context(&ctx, &commitments, &output_notes);
        let ring_proof = note_membership::prove(
            &self.key,
            &self.notes,
            ring,
            eligibility,
            position,
            &opening.serial,
            &(opening.blinding - pseudo_effective),
            &pseudo,
            &membership_context,
            rng,
        )?;
        Ok(Spend {
            proof: SpendProof {
                serial_point,
                pseudo,
                ring: ring_proof,
                outputs: commitments,
                output_notes,
                output_range,
                output_range_commitments,
                balance,
                tag: *tag,
            },
            notes,
            // Against the tag, not against the bare generator: a settlement
            // that links an output to an instruction needs the blinding the
            // output's own commitment was made with, and taking the bare one
            // is how a tagged leg silently stops verifying.
            tagged_blindings: blindings,
        })
    }

    pub fn check_spend<R: RngCore + CryptoRng>(
        &self,
        ring: &[usize],
        proof: &SpendProof,
        context: &[u8],
        rng: &mut R,
    ) -> Result<(), &'static str> {
        let eligibility = vec![true; ring.len()];
        self.check_spend_constrained(ring, proof, &eligibility, context, rng)
    }

    pub fn check_spend_constrained<R: RngCore + CryptoRng>(
        &self,
        ring: &[usize],
        proof: &SpendProof,
        eligibility: &[bool],
        context: &[u8],
        _rng: &mut R,
    ) -> Result<(), &'static str> {
        let key = proof.serial_point.compress().to_bytes();
        if self.spent.contains(&key) {
            return Err("serial already spent");
        }
        let ctx = Self::tagged_context(context, &proof.tag);
        if proof.outputs.len() != proof.output_notes.len() {
            return Err("output note binding count mismatch");
        }
        if ring.len() != eligibility.len() || ring.iter().any(|i| *i >= self.notes.len()) {
            return Err("the ring names an absent note");
        }
        let unique: HashSet<_> = ring.iter().collect();
        if unique.len() != ring.len() {
            return Err("the ring repeats a note");
        }

        let membership_context =
            Self::membership_context(&ctx, &proof.outputs, &proof.output_notes);
        if !note_membership::verify(
            &self.key,
            &self.notes,
            ring,
            eligibility,
            &proof.pseudo,
            &proof.serial_point,
            &membership_context,
            &proof.ring,
        ) {
            return Err("no note in the ring carries this serial");
        }

        let pc = PedersenGens {
            B: proof.tag,
            B_blinding: self.key.h,
        };
        if proof.output_range_commitments.len() != proof.outputs.len()
            || proof
                .output_range_commitments
                .iter()
                .zip(proof.outputs.iter())
                .any(|(c, o)| *c != o.compress())
        {
            return Err("the range proof is about other outputs");
        }
        proof
            .output_range
            .verify_multiple(
                &self.gens,
                &pc,
                &mut Self::range_transcript(&ctx),
                &proof.output_range_commitments,
                self.bits,
            )
            .map_err(|_| "an output is not shown to be in range")?;

        let residual = proof.pseudo - proof.outputs.iter().sum::<RistrettoPoint>();
        if !verify_zero_opening(
            &self.key,
            &mut Self::balance_transcript(&ctx),
            &residual,
            &proof.balance,
        ) {
            return Err("outputs do not add up to the note being spent");
        }
        Ok(())
    }

    pub fn apply_spend(
        &mut self,
        proof: &SpendProof,
        notes: Vec<Note>,
    ) -> Result<(), &'static str> {
        if !proof.matches_output_notes(&notes) {
            return Err("delivered notes differ from signed destinations");
        }
        let key = proof.serial_point.compress().to_bytes();
        if !self.spent.insert(key) {
            return Err("serial already spent");
        }
        self.rolling.update(b"s");
        self.rolling.update(key);
        // spent notes stay in the pool: removing them would say which one went
        // balanced against the note that funded them, so not issuance
        for note in notes {
            self.append(note);
        }
        Ok(())
    }

    /// Compute the exact post-spend root without changing either rail, so a
    /// fallible receipt signer runs before irreversible in-memory admission.
    pub(crate) fn spend_snapshot(
        &self,
        proof: &SpendProof,
        notes: &[Note],
    ) -> Result<[u8; 32], &'static str> {
        if !proof.matches_output_notes(notes) {
            return Err("delivered notes differ from signed destinations");
        }
        let serial = proof.serial_point.compress().to_bytes();
        if self.spent.contains(&serial) {
            return Err("serial already spent");
        }
        let mut rolling = self.rolling.clone();
        rolling.update(b"s");
        rolling.update(serial);
        for note in notes {
            rolling.update(self.commitment_of(note).compress().as_bytes());
        }
        Ok(rolling.finalize().into())
    }

    /// The state root, in constant time.
    ///
    /// This used to walk the whole ledger --- compressing every note that had
    /// ever existed and re-sorting every spent serial --- and a settlement
    /// takes four of them, two rails before and after. `benches/rings.rs`
    /// measured what that costs: 4.3 us a note, so 17.7 ms of root against
    /// 8 ms of cryptography at a thousand notes, and 93.5 ms against the same
    /// 8 ms at four thousand. A settlement cost proportional to total history
    /// is the one thing the account rail was careful not to have.
    ///
    /// Nothing about the ledger required it. Notes are only ever appended ---
    /// spent ones stay in the pool, because removing one would say which it
    /// was --- and serials are only ever inserted, so the hash of the whole
    /// history is a running hash extended once per change. The sort was buying
    /// order-independence for a sequence that already has an order: the one
    /// the chain applied.
    /// Whether this serial has already been published.
    ///
    /// Exposed so an outflow disclosure can be checked against the ledger by
    /// somebody who is not the wallet. Knowing that a serial was spent reveals
    /// nothing on its own --- it appears in public exactly once.
    ///
    /// Version 2 stores the Triptych linking tag `U/S`, never the scalar or the
    /// note's publicly searchable one-time key `g^S`.
    pub fn is_spent(&self, serial: &Scalar) -> bool {
        self.spent
            .contains(&note_nullifier(serial).compress().to_bytes())
    }

    pub fn snapshot(&self) -> [u8; 32] {
        self.rolling.clone().finalize().into()
    }
}

/// Decoys drawn from the newest `window` notes, with the real note inside.
///
/// `ring_for` draws uniformly over the whole pool, and that is only an
/// anonymity set if a real spend is uniform over the whole pool too. It is not:
/// a settlement pays with a note it was paid, so the spent note is recent, and
/// a uniform decoy usually is not. An observer that guesses the newest member
/// of the ring then wins far more often than one over the ring size ---
/// `benches/rings.rs` measures how much more.
///
/// The fix is to draw the decoys from where the real ones come from. `window`
/// is how far back that is, in notes; a pool shorter than the window falls back
/// to the whole pool, which is the same thing when there is no history to
/// stand out against.
pub fn ring_recent(
    pool: usize,
    index: usize,
    size: usize,
    window: usize,
    seed: u64,
) -> Result<Vec<usize>, &'static str> {
    if size < 2 || !size.is_power_of_two() {
        return Err("ring size must be a power of two, at least two");
    }
    if pool < size {
        return Err("the pool is smaller than the ring");
    }
    if index >= pool {
        return Err("the note is not in the pool");
    }
    // The window has to hold the ring, and it has to reach back far enough to
    // cover the real note --- a window that excluded it would name it outright.
    let span = window.max(size).max(pool - index);
    let span = span.min(pool);
    let floor = pool - span;
    let mut ring: Vec<usize> = Vec::with_capacity(size);
    ring.push(index);
    let mut state = seed | 1;
    while ring.len() < size {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let candidate = floor + (state >> 33) as usize % span;
        if !ring.contains(&candidate) {
            ring.push(candidate);
        }
    }
    for i in (1..ring.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ring.swap(i, (state >> 33) as usize % (i + 1));
    }
    Ok(ring)
}

/// Decoys drawn from the pool, with the real note somewhere inside.
pub fn ring_for(
    pool: usize,
    index: usize,
    size: usize,
    seed: u64,
) -> Result<Vec<usize>, &'static str> {
    if size < 2 || !size.is_power_of_two() {
        return Err("ring size must be a power of two, at least two");
    }
    if pool < size {
        return Err("the pool is smaller than the ring");
    }
    let mut ring: Vec<usize> = Vec::with_capacity(size);
    ring.push(index);
    let mut state = seed | 1;
    while ring.len() < size {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let candidate = (state >> 33) as usize % pool;
        if !ring.contains(&candidate) {
            ring.push(candidate);
        }
    }
    // deterministic shuffle, so the real note is not always first
    for i in (1..ring.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ring.swap(i, (state >> 33) as usize % (i + 1));
    }
    let _ = RistrettoPoint::identity();
    Ok(ring)
}
