//! One-out-of-N membership with a scope nullifier, by OR composition.
//!
//! The statement is: *I know the discrete log of one of these public points,
//! and this nullifier is that same secret applied to the scope generator.* The
//! second half is what makes the proof countable — every wallet of one entity
//! produces the same nullifier inside a scope, so a per-entity limit can be
//! enforced without learning which entity it is, and the nullifier does not
//! carry across scopes.
//!
//! Composition is the classic Cramer--Damgård--Schoenmakers trick: simulate
//! every branch but the real one, then force the challenges to sum to the
//! transcript's. Proof size and verifier cost are linear in the registry, which
//! is the right trade below about sixteen entries and the wrong one above it ---
//! `oneofmany` carries the logarithmic alternative and the crossover.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

use crate::sigma::TranscriptExt;

/// Everything the verifier already knows.
pub struct Statement<'a> {
    pub registry_id: &'a [u8],
    pub points: &'a [RistrettoPoint],
    pub scope: &'a [u8],
    pub context_hash: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub nullifier: RistrettoPoint,
    pub challenges: Vec<Scalar>,
    pub responses: Vec<Scalar>,
}

impl Proof {
    /// What goes on the wire: one point plus two scalars per registry entry.
    pub fn size_bytes(&self) -> usize {
        32 + 64 * self.challenges.len()
    }
}

pub fn scope_generator(scope: &[u8]) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(scope)
}

/// The nullifier a venue counts against: equal across an entity's wallets,
/// unrelated across scopes.
pub fn nullifier(scope: &[u8], secret: &Scalar) -> RistrettoPoint {
    scope_generator(scope) * secret
}

fn challenge(
    statement: &Statement,
    nullifier: &RistrettoPoint,
    commit_g: &[RistrettoPoint],
    commit_h: &[RistrettoPoint],
) -> Scalar {
    let mut t = Transcript::new(b"qomm:or-dleq:v1");
    t.append_message(b"registry", statement.registry_id);
    t.append_message(b"scope", statement.scope);
    t.append_message(b"context", statement.context_hash);
    t.append_point(b"N", nullifier);
    for point in statement.points {
        t.append_point(b"P", point);
    }
    for point in commit_g {
        t.append_point(b"A", point);
    }
    for point in commit_h {
        t.append_point(b"B", point);
    }
    t.challenge_scalar(b"c")
}

pub fn prove<R: RngCore + CryptoRng>(
    statement: &Statement,
    secret: &Scalar,
    index: usize,
    rng: &mut R,
) -> Result<Proof, &'static str> {
    let n = statement.points.len();
    if index >= n {
        return Err("the witness is not in this registry");
    }
    let h_scope = scope_generator(statement.scope);
    let null = h_scope * secret;
    if statement.points[index] != RISTRETTO_BASEPOINT_POINT * secret {
        return Err("the secret does not open the point at that index");
    }

    let mut challenges = vec![Scalar::ZERO; n];
    let mut responses = vec![Scalar::ZERO; n];
    let mut commit_g = vec![RistrettoPoint::identity(); n];
    let mut commit_h = vec![RistrettoPoint::identity(); n];

    let witness_nonce = Scalar::random(rng);
    for (position, point) in statement.points.iter().enumerate() {
        if position == index {
            commit_g[position] = RISTRETTO_BASEPOINT_POINT * witness_nonce;
            commit_h[position] = h_scope * witness_nonce;
            continue;
        }
        // simulate: pick the response and challenge, then derive the commitment
        challenges[position] = Scalar::random(rng);
        responses[position] = Scalar::random(rng);
        commit_g[position] =
            RISTRETTO_BASEPOINT_POINT * responses[position] - point * challenges[position];
        commit_h[position] = h_scope * responses[position] - null * challenges[position];
    }

    let total = challenge(statement, &null, &commit_g, &commit_h);
    let others: Scalar = challenges.iter().sum();
    challenges[index] = total - others;
    responses[index] = witness_nonce + challenges[index] * secret;
    Ok(Proof {
        nullifier: null,
        challenges,
        responses,
    })
}

pub fn verify(statement: &Statement, proof: &Proof) -> bool {
    let n = statement.points.len();
    if proof.challenges.len() != n || proof.responses.len() != n {
        return false;
    }
    let h_scope = scope_generator(statement.scope);
    let commit_g: Vec<RistrettoPoint> = (0..n)
        .map(|i| {
            RISTRETTO_BASEPOINT_POINT * proof.responses[i]
                - statement.points[i] * proof.challenges[i]
        })
        .collect();
    let commit_h: Vec<RistrettoPoint> = (0..n)
        .map(|i| h_scope * proof.responses[i] - proof.nullifier * proof.challenges[i])
        .collect();
    let total = challenge(statement, &proof.nullifier, &commit_g, &commit_h);
    let sum: Scalar = proof.challenges.iter().sum();
    sum == total
}
