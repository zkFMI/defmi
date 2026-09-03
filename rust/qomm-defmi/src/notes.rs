//! Balances that do not sit at an address.
//!
//! A holding is a note `C = g^S · A_a^v · h^r`. The recipient, not the sender,
//! controls the serial: an address is `(A, B) = (g^a, g^b)`, a sender draws an
//! ephemeral `e`, publishes `E = g^e`, and builds against `g^{H(A^e)}·B`. That
//! point is computable from public data but `S = H(A^e) + b` is not, so a
//! sender can address a note it cannot spend.
//!
//! Spending publishes `g^S` --- never the scalar, which would hand the sender
//! the payee's long-term spend key --- with a proof that it is a bare power of
//! the base point, and a one-out-of-many proof that some note in a ring
//! satisfies `C_i / (g^S · C') = h^*`. Without the bare-power proof the serial
//! could be published as `g^S h^u` for any known u, giving a fresh nullifier
//! every time and making double spending free.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{Signature, VerifyingKey};
use merlin::Transcript;
use qomm_zk::oneofmany::{self, GkProof};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{opening_terms, prove_opening, Batch, OpeningProof, TranscriptExt};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::collections::HashSet;

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
}

/// The two secrets behind an address, split because they do different jobs: the
/// view key finds your own notes and could be handed to an auditor, while only
/// the spend key turns a note into a serial number.
pub struct Wallet {
    view: Scalar,
    spend: Scalar,
    pub address: Address,
}

impl Wallet {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let view = Scalar::random(rng);
        let spend = Scalar::random(rng);
        Wallet {
            view,
            spend,
            address: Address {
                view: G * view,
                spend: G * spend,
            },
        }
    }

    /// A wallet from scalars somebody else derived.
    ///
    /// `viewing.rs` derives a pair per scope from one seed, so that handing an
    /// auditor one scope's view key hands it that scope and nothing else. The
    /// wallet is otherwise ordinary: this is what spends.
    pub fn from_parts(view: Scalar, spend: Scalar) -> Self {
        Wallet {
            view,
            spend,
            address: Address {
                view: G * view,
                spend: G * spend,
            },
        }
    }

    /// The half that finds notes and cannot move them.
    pub fn view_key(&self) -> ViewKey {
        ViewKey { scalar: self.view }
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
}

impl ViewKey {
    pub fn new(scalar: Scalar) -> Self {
        ViewKey { scalar }
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
    pub masked_value: Scalar,
    pub masked_blinding: Scalar,
}

#[derive(Clone, Copy)]
pub struct Opening {
    pub value: u64,
    pub blinding: Scalar,
    pub serial: Scalar,
}

/// Knowledge of the discrete log of the published serial point.
pub struct SerialProof {
    pub t: RistrettoPoint,
    pub z: Scalar,
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
    pub serial_proof: SerialProof,
    pub pseudo: RistrettoPoint,
    pub ring: GkProof,
    pub outputs: Vec<RistrettoPoint>,
    pub output_range: RangeProof,
    pub output_range_commitments: Vec<CompressedRistretto>,
    pub balance: OpeningProof,
    pub tag: RistrettoPoint,
}

const SPEND_PROOF_WIRE_MAGIC: &[u8] = b"QOMMNSP1";
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
    fn push_scalars(out: &mut Vec<u8>, values: &[Scalar]) -> Result<(), String> {
        if values.len() > MAX_SPEND_VECTOR {
            return Err("note-spend proof scalar vector exceeds its bound".into());
        }
        out.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for value in values {
            push_scalar(out, value);
        }
        Ok(())
    }

    let mut out = Vec::new();
    out.extend_from_slice(SPEND_PROOF_WIRE_MAGIC);
    push_point(&mut out, &proof.serial_point);
    push_point(&mut out, &proof.serial_proof.t);
    push_scalar(&mut out, &proof.serial_proof.z);
    push_point(&mut out, &proof.pseudo);
    push_points(&mut out, &proof.ring.cl)?;
    push_points(&mut out, &proof.ring.ca)?;
    push_points(&mut out, &proof.ring.cb)?;
    push_points(&mut out, &proof.ring.gk)?;
    push_scalars(&mut out, &proof.ring.f)?;
    push_scalars(&mut out, &proof.ring.za)?;
    push_scalars(&mut out, &proof.ring.zb)?;
    push_scalar(&mut out, &proof.ring.zd);
    push_points(&mut out, &proof.outputs)?;
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
        fn scalars(&mut self) -> Result<Vec<Scalar>, String> {
            let count = self.count()?;
            (0..count).map(|_| self.scalar()).collect()
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
    let serial_proof = SerialProof {
        t: reader.point()?,
        z: reader.scalar()?,
    };
    let pseudo = reader.point()?;
    let ring = GkProof {
        cl: reader.points()?,
        ca: reader.points()?,
        cb: reader.points()?,
        gk: reader.points()?,
        f: reader.scalars()?,
        za: reader.scalars()?,
        zb: reader.scalars()?,
        zd: reader.scalar()?,
    };
    let outputs = reader.points()?;
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
        serial_proof,
        pseudo,
        ring,
        outputs,
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
        fn scalars(hash: &mut sha2::Sha256, values: &[Scalar]) {
            hash.update((values.len() as u64).to_be_bytes());
            for value in values {
                scalar(hash, value);
            }
        }
        let mut hash = sha2::Sha256::new();
        hash.update(b"QOMM:DEFMI:NOTE-SPEND-PROOF:v1");
        point(&mut hash, &self.serial_point);
        point(&mut hash, &self.serial_proof.t);
        scalar(&mut hash, &self.serial_proof.z);
        point(&mut hash, &self.pseudo);
        points(&mut hash, &self.ring.cl);
        points(&mut hash, &self.ring.ca);
        points(&mut hash, &self.ring.cb);
        points(&mut hash, &self.ring.gk);
        scalars(&mut hash, &self.ring.f);
        scalars(&mut hash, &self.ring.za);
        scalars(&mut hash, &self.ring.zb);
        scalar(&mut hash, &self.ring.zd);
        points(&mut hash, &self.outputs);
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
    issuer: Option<VerifyingKey>,
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

    fn masks(&self, shared: &Scalar) -> (Scalar, Scalar) {
        let encoded = shared.to_bytes();
        (
            scalar_from(b"mask:value", &[&encoded]),
            scalar_from(b"mask:blinding", &[&encoded]),
        )
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
    ) -> Note {
        let ephemeral_secret = Scalar::random(rng);
        let ephemeral = G * ephemeral_secret;
        let shared = scalar_from(
            b"shared",
            &[(address.view * ephemeral_secret).compress().as_bytes()],
        );
        let (mv, mb) = self.masks(&shared);
        Note {
            one_time: self.one_time_point(address, &shared),
            value_commitment,
            ephemeral,
            masked_value: Scalar::from(value) + mv,
            masked_blinding: effective_blinding + mb,
        }
    }

    pub fn commitment_of(&self, note: &Note) -> RistrettoPoint {
        note.one_time + note.value_commitment
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
        authorisation: &Signature,
    ) -> Result<usize, &'static str> {
        let issuer = self.issuer.as_ref().ok_or("this ledger has no issuer")?;
        let body = note_issuance_body(&self.commitment_of(&note), nonce);
        if self.issued.contains(&body) {
            return Err("that issuance authorisation was already used");
        }
        issuer
            .verify_strict(&body, authorisation)
            .map_err(|_| "the note is not signed by the issuer")?;
        self.issued.insert(body);
        Ok(self.append(note))
    }

    /// A ledger where notes can only come from one place.
    pub fn under_issuer(mut self, issuer: VerifyingKey) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// One scalar multiplication per note; no trial decryption of amounts.
    pub fn scan(&self, wallet: &Wallet, asset_key: &Pedersen) -> Vec<(usize, Opening)> {
        let mut found = Vec::new();
        for (index, note) in self.notes.iter().enumerate() {
            let shared = wallet.shared(&note.ephemeral);
            let (mv, mb) = self.masks(&shared);
            let value_scalar = note.masked_value - mv;
            let blinding = note.masked_blinding - mb;
            // recover the value only if it is a small integer
            let Some(value) = small_scalar(&value_scalar, self.bits) else {
                continue;
            };
            let expected = self.one_time_point(&wallet.address, &shared)
                + asset_key.commit_u64(value, &blinding);
            if expected == self.commitment_of(note) {
                found.push((
                    index,
                    Opening {
                        value,
                        blinding,
                        serial: wallet.serial(&note.ephemeral),
                    },
                ));
            }
        }
        found
    }

    /// Every note addressed to `address` that this view key can open, and the
    /// amounts --- but no serial numbers, because a serial needs the spend key.
    ///
    /// One scalar multiplication a note, the same as a wallet scanning for
    /// itself. What differs is the tuple that comes back: there is nowhere to
    /// put a serial, so an auditor cannot be handed one by accident.
    pub fn scan_view(
        &self,
        view: &ViewKey,
        address: &Address,
        asset_key: &Pedersen,
    ) -> Vec<(usize, u64, Scalar)> {
        let mut found = Vec::new();
        for (index, note) in self.notes.iter().enumerate() {
            let shared = view.shared(&note.ephemeral);
            let (mv, mb) = self.masks(&shared);
            let value_scalar = note.masked_value - mv;
            let blinding = note.masked_blinding - mb;
            let Some(value) = small_scalar(&value_scalar, self.bits) else {
                continue;
            };
            let expected =
                self.one_time_point(address, &shared) + asset_key.commit_u64(value, &blinding);
            if expected == self.commitment_of(note) {
                found.push((index, value, blinding));
            }
        }
        found
    }

    fn serial_transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:note:serial");
        t.append_message(b"ctx", context);
        t
    }
    fn ring_transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"qomm:note:ring");
        t.append_message(b"ctx", context);
        t
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
        let total: u64 = outputs.iter().map(|(_, v)| *v).sum();
        if total != opening.value {
            return Err("outputs do not sum to the note being spent");
        }
        let ctx = Self::tagged_context(context, tag);
        let tagged = self.key.with_value_generator(*tag);
        let pc = PedersenGens {
            B: *tag,
            B_blinding: self.key.h,
        };

        let serial_point = G * opening.serial;
        let serial_proof = self.prove_serial(&serial_point, &opening.serial, &ctx, rng);

        let pseudo_blinding = Scalar::random(rng);
        let pseudo = tagged.commit_u64(opening.value, &pseudo_blinding);
        let pseudo_effective = gamma * Scalar::from(opening.value) + pseudo_blinding;

        let offset = serial_point + pseudo;
        let members: Vec<RistrettoPoint> = ring
            .iter()
            .zip(eligibility)
            .enumerate()
            .map(|(position, (i, eligible))| {
                self.constrained_member(*i, position, *eligible, &offset, &ctx)
            })
            .collect();
        let ring_proof = oneofmany::prove(
            &self.key,
            &mut Self::ring_transcript(&ctx),
            &members,
            position,
            &(opening.blinding - pseudo_effective),
            rng,
        )?;

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
            ));
            commitments.push(commitment);
        }
        let residual = pseudo - commitments.iter().sum::<RistrettoPoint>();
        let tagged_sum: Scalar = blindings.iter().sum();
        let balance = prove_opening(
            &self.key,
            &mut Self::balance_transcript(&ctx),
            &residual,
            &Scalar::ZERO,
            &(pseudo_blinding - tagged_sum),
            rng,
        );
        Ok(Spend {
            proof: SpendProof {
                serial_point,
                serial_proof,
                pseudo,
                ring: ring_proof,
                outputs: commitments,
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

    fn constrained_member(
        &self,
        note_index: usize,
        position: usize,
        eligible: bool,
        offset: &RistrettoPoint,
        context: &[u8],
    ) -> RistrettoPoint {
        let commitment = self.commitment_of(&self.notes[note_index]);
        if eligible {
            return commitment - offset;
        }
        let position = (position as u64).to_be_bytes();
        let mut penalty = scalar_from(
            b"ring-ineligible",
            &[context, commitment.compress().as_bytes(), &position],
        );
        if penalty == Scalar::ZERO {
            penalty = Scalar::ONE;
        }
        commitment - offset + G * penalty
    }

    fn prove_serial<R: RngCore + CryptoRng>(
        &self,
        point: &RistrettoPoint,
        serial: &Scalar,
        context: &[u8],
        rng: &mut R,
    ) -> SerialProof {
        let witness = Scalar::random(rng);
        let t = G * witness;
        let mut transcript = Self::serial_transcript(context);
        transcript.append_point(b"N", point);
        transcript.append_point(b"T", &t);
        let c = transcript.challenge_scalar(b"c");
        SerialProof {
            t,
            z: witness + c * serial,
        }
    }

    fn check_serial(&self, point: &RistrettoPoint, proof: &SerialProof, context: &[u8]) -> bool {
        let mut transcript = Self::serial_transcript(context);
        transcript.append_point(b"N", point);
        transcript.append_point(b"T", &proof.t);
        let c = transcript.challenge_scalar(b"c");
        G * proof.z == proof.t + point * c
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
        rng: &mut R,
    ) -> Result<(), &'static str> {
        let key = proof.serial_point.compress().to_bytes();
        if self.spent.contains(&key) {
            return Err("serial already spent");
        }
        let ctx = Self::tagged_context(context, &proof.tag);
        if !self.check_serial(&proof.serial_point, &proof.serial_proof, &ctx) {
            return Err("the serial is not a bare power of the base point");
        }
        if ring.len() != eligibility.len() || ring.iter().any(|i| *i >= self.notes.len()) {
            return Err("the ring names an absent note");
        }
        let unique: HashSet<_> = ring.iter().collect();
        if unique.len() != ring.len() {
            return Err("the ring repeats a note");
        }

        let offset = proof.serial_point + proof.pseudo;
        let members: Vec<RistrettoPoint> = ring
            .iter()
            .zip(eligibility)
            .enumerate()
            .map(|(position, (i, eligible))| {
                self.constrained_member(*i, position, *eligible, &offset, &ctx)
            })
            .collect();
        if !oneofmany::verify(
            &self.key,
            &mut Self::ring_transcript(&ctx),
            &members,
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
        let mut batch = Batch::new();
        let (s, p) = opening_terms(
            &self.key,
            &mut Self::balance_transcript(&ctx),
            &residual,
            &proof.balance,
            &Batch::weight(rng),
        );
        batch.push(s, p);
        if !batch.verify() {
            return Err("outputs do not add up to the note being spent");
        }
        Ok(())
    }

    pub fn apply_spend(
        &mut self,
        proof: &SpendProof,
        notes: Vec<Note>,
    ) -> Result<(), &'static str> {
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
    /// What the spent set holds is `g^S` and not `S`, because that is what a
    /// spend publishes. Comparing the scalar to it silently matched nothing,
    /// which is the kind of wrong a test finds and a reading does not.
    pub fn is_spent(&self, serial: &Scalar) -> bool {
        self.spent.contains(&(G * serial).compress().to_bytes())
    }

    pub fn snapshot(&self) -> [u8; 32] {
        self.rolling.clone().finalize().into()
    }
}

/// Recover a small integer from a scalar, or nothing.
fn small_scalar(scalar: &Scalar, bits: usize) -> Option<u64> {
    let bytes = scalar.to_bytes();
    if bytes[8..].iter().any(|b| *b != 0) {
        return None;
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[..8]);
    let value = u64::from_le_bytes(value);
    if bits < 64 && value >= (1u64 << bits) {
        return None;
    }
    Some(value)
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
