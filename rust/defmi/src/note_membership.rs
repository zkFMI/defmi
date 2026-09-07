//! Adapter of Tari Triptych's unchanged parallel/RingCT proof API.
//! Source: bf0cb42fff55636a8bb037020411fb3a050af23f, BSD-3-Clause.
//! We bind the same ring index to a one-time owner key and a value commitment,
//! and use the library's unlinkable linking tag rather than publishing that key.
//! The upstream implementation is experimental; this is not an audit claim.

use crate::notes::Note;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, RistrettoPoint, Scalar};
use merlin::Transcript;
use zkfmi_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::sync::OnceLock;
use triptych::parallel::{
    TriptychInputSet, TriptychParameters, TriptychProof, TriptychStatement, TriptychWitness,
};

const MAX_RING: usize = 4096;
const MAX_PROOF: usize = 8 + 32 * (8 + 4 * 12);

fn linking_generator() -> &'static RistrettoPoint {
    static GENERATOR: OnceLock<RistrettoPoint> = OnceLock::new();
    GENERATOR.get_or_init(|| {
        *TriptychParameters::new(2, 2)
            .expect("constant valid Triptych parameters")
            .get_U()
    })
}

pub fn nullifier(serial: &Scalar) -> RistrettoPoint {
    serial.invert() * linking_generator()
}

/// Bounded canonical wire wrapper; proof equations remain upstream.
pub struct NoteMembershipProof(TriptychProof);

impl NoteMembershipProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
    pub fn size_bytes(&self) -> usize {
        self.0.to_bytes().len()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8
            || bytes.len() > MAX_PROOF
            || u32::from_le_bytes(bytes[..4].try_into().unwrap()) != 1
            || !(2..=12).contains(&u32::from_le_bytes(bytes[4..8].try_into().unwrap()))
        {
            return Err("note membership proof dimensions are invalid");
        }
        let proof =
            TriptychProof::from_bytes(bytes).map_err(|_| "malformed note membership proof")?;
        if proof.to_bytes() != bytes {
            return Err("non-canonical note membership proof");
        }
        Ok(Self(proof))
    }
}

fn statement(
    key: &Pedersen,
    notes: &[Note],
    ring: &[usize],
    eligibility: &[bool],
    pseudo: &RistrettoPoint,
    serial: &RistrettoPoint,
    context: &[u8],
) -> Result<(TriptychParameters, TriptychStatement), &'static str> {
    if ring.is_empty()
        || ring.len() > MAX_RING
        || ring.len() != eligibility.len()
        || ring.iter().any(|i| *i >= notes.len())
    {
        return Err("invalid note membership ring");
    }
    let exponent = ring.len().next_power_of_two().trailing_zeros().max(2);
    let params =
        TriptychParameters::new_with_generators(2, exponent, &G, &key.h, linking_generator())
            .map_err(|_| "invalid note membership generators")?;
    let mut owners = Vec::with_capacity(ring.len());
    let mut values = Vec::with_capacity(ring.len());
    for (position, (index, eligible)) in ring.iter().zip(eligibility).enumerate() {
        let note = &notes[*index];
        // Ineligible positions get an unknown-discrete-log point, not a known
        // scalar offset that a malicious owner can absorb into a signing key.
        let owner = if *eligible {
            note.one_time
        } else {
            let bytes: [u8; 64] = Sha512::new()
                .chain_update(b"DEFMI:NOTE:INELIGIBLE:v2")
                .chain_update((context.len() as u64).to_be_bytes())
                .chain_update(context)
                .chain_update((position as u64).to_be_bytes())
                .chain_update(note.one_time.compress().as_bytes())
                .chain_update(note.value_commitment.compress().as_bytes())
                .finalize()
                .into();
            RistrettoPoint::from_uniform_bytes(&bytes)
        };
        owners.push(owner);
        values.push(note.value_commitment);
    }
    // Repeating the final pair only duplicates an existing possible witness;
    // it neither creates an eligible owner nor changes the linking tag.
    let inputs = TriptychInputSet::new_with_padding(&owners, &values, &params)
        .map_err(|_| "invalid note membership input set")?;
    let statement = TriptychStatement::new(&params, &inputs, pseudo, serial)
        .map_err(|_| "invalid note membership statement")?;
    Ok((params, statement))
}

fn transcript(context: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(b"DEFMI:NOTE:MEMBERSHIP:v2");
    transcript.append_message(b"context", context);
    transcript
}

#[allow(clippy::too_many_arguments)]
pub fn prove<R: RngCore + CryptoRng>(
    key: &Pedersen,
    notes: &[Note],
    ring: &[usize],
    eligibility: &[bool],
    position: usize,
    serial_secret: &Scalar,
    blinding_difference: &Scalar,
    pseudo: &RistrettoPoint,
    context: &[u8],
    rng: &mut R,
) -> Result<NoteMembershipProof, &'static str> {
    let serial = nullifier(serial_secret);
    let (params, statement) = statement(key, notes, ring, eligibility, pseudo, &serial, context)?;
    let witness =
        TriptychWitness::new(&params, position as u32, serial_secret, blinding_difference)
            .map_err(|_| "invalid note membership witness")?;
    TriptychProof::prove_with_rng(&witness, &statement, rng, &mut transcript(context))
        .map(NoteMembershipProof)
        .map_err(|_| "note membership witness does not match the ring")
}

#[allow(clippy::too_many_arguments)]
pub fn verify(
    key: &Pedersen,
    notes: &[Note],
    ring: &[usize],
    eligibility: &[bool],
    pseudo: &RistrettoPoint,
    serial: &RistrettoPoint,
    context: &[u8],
    proof: &NoteMembershipProof,
) -> bool {
    statement(key, notes, ring, eligibility, pseudo, serial, context)
        .is_ok_and(|(_, statement)| proof.0.verify(&statement, &mut transcript(context)).is_ok())
}
