//! The sigma protocols this system needs, none of which an audited crate
//! provides.
//!
//! The crates that do exist for this — `sigma-proofs`, `sigma-protocols`,
//! `sigma_fun` — either say outright that they are not ready for production or
//! carry no audit, so there is nothing to defer to here. Range proofs and group
//! arithmetic *do* have audited implementations and are not reimplemented; see
//! `range.rs`.
//!
//! Everything verifies in batch. A sigma check has the shape `P^z Q^w == T C^c`,
//! and a random linear combination collapses any number of them into one
//! multiscalar multiplication. That is the operation the Python version could
//! not make pay: a point addition there costs a quarter of a scalar
//! multiplication because of the call overhead, against 1/256 here, so batching
//! made things slower rather than faster.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use crate::pedersen::Pedersen;

pub trait TranscriptExt {
    fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptExt for Transcript {
    fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        self.append_message(label, point.compress().as_bytes());
    }
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
}

/// Knowledge of an opening of `C = g^value h^blinding`.
#[derive(Clone, Debug)]
pub struct OpeningProof {
    pub t: RistrettoPoint,
    pub z_value: Scalar,
    pub z_blinding: Scalar,
}

pub fn prove_opening<R: RngCore + CryptoRng>(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitment: &RistrettoPoint,
    value: &Scalar,
    blinding: &Scalar,
    rng: &mut R,
) -> OpeningProof {
    let k_value = Scalar::random(rng);
    let k_blinding = Scalar::random(rng);
    let t = key.g * k_value + key.h * k_blinding;
    let c = opening_challenge(transcript, commitment, &t);
    OpeningProof {
        t,
        z_value: k_value + c * value,
        z_blinding: k_blinding + c * blinding,
    }
}

/// Derive the Fiat--Shamir challenge for an opening proof.
///
/// Threshold assemblers need the challenge before they can form their partial
/// responses. Keeping the transcript framing here ensures those assemblers use
/// exactly the same ordinary proof format as [`prove_opening`].
pub fn opening_challenge(
    transcript: &mut Transcript,
    commitment: &RistrettoPoint,
    t: &RistrettoPoint,
) -> Scalar {
    transcript.append_message(b"dom", b"qomm/opening");
    transcript.append_point(b"C", commitment);
    transcript.append_point(b"T", t);
    transcript.challenge_scalar(b"c")
}

/// The verification equation, rearranged to sum to the identity so a batch can
/// share one multiscalar multiplication.
pub fn opening_terms(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitment: &RistrettoPoint,
    proof: &OpeningProof,
    weight: &Scalar,
) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
    let c = opening_challenge(transcript, commitment, &proof.t);
    (
        vec![
            weight * proof.z_value,
            weight * proof.z_blinding,
            -weight,
            -(weight * c),
        ],
        vec![key.g, key.h, proof.t, *commitment],
    )
}

pub fn verify_opening(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitment: &RistrettoPoint,
    proof: &OpeningProof,
) -> bool {
    let (scalars, points) = opening_terms(key, transcript, commitment, proof, &Scalar::ONE);
    RistrettoPoint::vartime_multiscalar_mul(&scalars, &points) == RistrettoPoint::identity()
}

/// Two commitments under different value generators hide the same number.
///
/// Needed because the computing quorum issues an instruction before anyone has
/// chosen a settlement tag, so the quantity is committed twice against
/// generators picked independently. One shared response ties them.
#[derive(Clone, Debug)]
pub struct CrossGeneratorProof {
    pub t_first: RistrettoPoint,
    pub t_second: RistrettoPoint,
    pub z_value: Scalar,
    pub z_first: Scalar,
    pub z_second: Scalar,
}

#[allow(clippy::too_many_arguments)]
pub fn prove_same_value<R: RngCore + CryptoRng>(
    key: &Pedersen,
    transcript: &mut Transcript,
    first_generator: &RistrettoPoint,
    second_generator: &RistrettoPoint,
    first_commitment: &RistrettoPoint,
    second_commitment: &RistrettoPoint,
    value: &Scalar,
    first_blinding: &Scalar,
    second_blinding: &Scalar,
    rng: &mut R,
) -> CrossGeneratorProof {
    let k_value = Scalar::random(rng);
    let k_first = Scalar::random(rng);
    let k_second = Scalar::random(rng);
    let t_first = first_generator * k_value + key.h * k_first;
    let t_second = second_generator * k_value + key.h * k_second;
    let c = cross_challenge(
        transcript,
        first_generator,
        second_generator,
        first_commitment,
        second_commitment,
        &t_first,
        &t_second,
    );
    CrossGeneratorProof {
        t_first,
        t_second,
        z_value: k_value + c * value,
        z_first: k_first + c * first_blinding,
        z_second: k_second + c * second_blinding,
    }
}

fn cross_challenge(
    transcript: &mut Transcript,
    g1: &RistrettoPoint,
    g2: &RistrettoPoint,
    c1: &RistrettoPoint,
    c2: &RistrettoPoint,
    t1: &RistrettoPoint,
    t2: &RistrettoPoint,
) -> Scalar {
    transcript.append_message(b"dom", b"qomm/xgen");
    transcript.append_point(b"g1", g1);
    transcript.append_point(b"g2", g2);
    transcript.append_point(b"c1", c1);
    transcript.append_point(b"c2", c2);
    transcript.append_point(b"t1", t1);
    transcript.append_point(b"t2", t2);
    transcript.challenge_scalar(b"c")
}

#[allow(clippy::too_many_arguments)]
pub fn same_value_terms(
    key: &Pedersen,
    transcript: &mut Transcript,
    first_generator: &RistrettoPoint,
    second_generator: &RistrettoPoint,
    first_commitment: &RistrettoPoint,
    second_commitment: &RistrettoPoint,
    proof: &CrossGeneratorProof,
    weight: &Scalar,
) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
    let c = cross_challenge(
        transcript,
        first_generator,
        second_generator,
        first_commitment,
        second_commitment,
        &proof.t_first,
        &proof.t_second,
    );
    // Powers of the weight, one per equation. A prover who satisfies neither
    // equation would need the polynomial w*E1 + w^2*E2 to vanish at a weight
    // drawn after the proof was fixed, which it does for at most two values.
    // **The weight has to be drawn by the verifier, at verification time.**
    // A transcript-derived weight is not enough: the prover can compute it too
    // and solve the single aggregate relation. `Batch::weight` is the only
    // sound source here; a lone verifier separates the equations instead ---
    // see `halves_hold`.
    let w2 = weight * weight;
    (
        vec![
            weight * proof.z_value,
            weight * proof.z_first,
            -weight,
            -(weight * c),
            w2 * proof.z_value,
            w2 * proof.z_second,
            -w2,
            -(w2 * c),
        ],
        vec![
            *first_generator,
            key.h,
            proof.t_first,
            *first_commitment,
            *second_generator,
            key.h,
            proof.t_second,
            *second_commitment,
        ],
    )
}

/// Check a weighted pair of equations by *separating* them rather than adding.
///
/// The weighted form above is sound when the weight is drawn after the proof is
/// fixed, which is what `Batch` does. A lone verifier has no such weight ---
/// and passing ONE, which is what these functions used to do, adds the two
/// equations before checking, so what gets verified is their sum. A sum of two
/// equations does not imply either of them. `verify_product` accepted a proof
/// that 2 x 3 = 8 for exactly this reason; the test that forges it is in
/// `tests/sigma.rs`.
///
/// Splitting the term list back into halves is safe because both builders emit
/// the two equations in order and of equal length, and it keeps one place where
/// the equations are written down.
fn halves_hold(scalars: &[Scalar], points: &[RistrettoPoint]) -> bool {
    debug_assert_eq!(scalars.len(), points.len());
    debug_assert_eq!(scalars.len() % 2, 0);
    let half = scalars.len() / 2;
    RistrettoPoint::vartime_multiscalar_mul(&scalars[..half], &points[..half])
        == RistrettoPoint::identity()
        && RistrettoPoint::vartime_multiscalar_mul(&scalars[half..], &points[half..])
            == RistrettoPoint::identity()
}

pub fn verify_same_value(
    key: &Pedersen,
    transcript: &mut Transcript,
    first_generator: &RistrettoPoint,
    second_generator: &RistrettoPoint,
    first_commitment: &RistrettoPoint,
    second_commitment: &RistrettoPoint,
    proof: &CrossGeneratorProof,
) -> bool {
    let (scalars, points) = same_value_terms(
        key,
        transcript,
        first_generator,
        second_generator,
        first_commitment,
        second_commitment,
        proof,
        &Scalar::ONE,
    );
    halves_hold(&scalars, &points)
}

/// The committed product, without opening any factor.
///
/// Uses `C_a^b = g^{ab} h^{r_a b}`, so `C_c / C_a^b` is a pure power of h.
/// Proving knowledge of one exponent b that opens `C_b` *and* relates `C_c` to
/// `C_a` therefore pins the product.
#[derive(Clone, Debug)]
pub struct ProductProof {
    pub t_factor: RistrettoPoint,
    pub t_product: RistrettoPoint,
    pub z_b: Scalar,
    pub z_rb: Scalar,
    pub z_s: Scalar,
}

#[allow(clippy::too_many_arguments)]
pub fn prove_product<R: RngCore + CryptoRng>(
    key: &Pedersen,
    transcript: &mut Transcript,
    c_a: &RistrettoPoint,
    a: &Scalar,
    r_a: &Scalar,
    b: &Scalar,
    r_b: &Scalar,
    r_c: &Scalar,
    rng: &mut R,
) -> ProductProof {
    let c_b = key.commit(b, r_b);
    let c_c = key.commit(&(a * b), r_c);
    let s = r_c - r_a * b;
    let k_b = Scalar::random(rng);
    let k_rb = Scalar::random(rng);
    let k_s = Scalar::random(rng);
    let t_factor = key.commit(&k_b, &k_rb);
    let t_product = c_a * k_b + key.h * k_s;
    let c = product_challenge(transcript, c_a, &c_b, &c_c, &t_factor, &t_product);
    ProductProof {
        t_factor,
        t_product,
        z_b: k_b + c * b,
        z_rb: k_rb + c * r_b,
        z_s: k_s + c * s,
    }
}

/// Derive the Fiat--Shamir challenge for a product proof.
///
/// This is public for threshold assembly: partial responses are formed only
/// after every first-move point has been combined. The transcript bytes remain
/// owned by this module, beside the ordinary prover and verifier.
pub fn product_challenge(
    transcript: &mut Transcript,
    c_a: &RistrettoPoint,
    c_b: &RistrettoPoint,
    c_c: &RistrettoPoint,
    t_factor: &RistrettoPoint,
    t_product: &RistrettoPoint,
) -> Scalar {
    transcript.append_message(b"dom", b"qomm/product");
    transcript.append_point(b"Ca", c_a);
    transcript.append_point(b"Cb", c_b);
    transcript.append_point(b"Cc", c_c);
    transcript.append_point(b"Tf", t_factor);
    transcript.append_point(b"Tp", t_product);
    transcript.challenge_scalar(b"c")
}

#[allow(clippy::too_many_arguments)]
pub fn product_terms(
    key: &Pedersen,
    transcript: &mut Transcript,
    c_a: &RistrettoPoint,
    c_b: &RistrettoPoint,
    c_c: &RistrettoPoint,
    proof: &ProductProof,
    weight: &Scalar,
) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
    let c = product_challenge(transcript, c_a, c_b, c_c, &proof.t_factor, &proof.t_product);
    let w2 = weight * weight;
    (
        vec![
            weight * proof.z_b,
            weight * proof.z_rb,
            -weight,
            -(weight * c),
            w2 * proof.z_b,
            w2 * proof.z_s,
            -w2,
            -(w2 * c),
        ],
        vec![
            key.g,
            key.h,
            proof.t_factor,
            *c_b,
            *c_a,
            key.h,
            proof.t_product,
            *c_c,
        ],
    )
}

pub fn verify_product(
    key: &Pedersen,
    transcript: &mut Transcript,
    c_a: &RistrettoPoint,
    c_b: &RistrettoPoint,
    c_c: &RistrettoPoint,
    proof: &ProductProof,
) -> bool {
    let (scalars, points) = product_terms(key, transcript, c_a, c_b, c_c, proof, &Scalar::ONE);
    halves_hold(&scalars, &points)
}

/// Collect independent checks and settle them with one multiscalar
/// multiplication.
#[derive(Default)]
pub struct Batch {
    scalars: Vec<Scalar>,
    points: Vec<RistrettoPoint>,
}

impl Batch {
    pub fn new() -> Self {
        Batch::default()
    }

    pub fn push(&mut self, scalars: Vec<Scalar>, points: Vec<RistrettoPoint>) {
        self.scalars.extend(scalars);
        self.points.extend(points);
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// Every check must be weighted independently, or a prover could satisfy
    /// the sum while satisfying none of them.
    pub fn weight<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        Scalar::random(rng)
    }

    pub fn verify(self) -> bool {
        if self.points.is_empty() {
            return true;
        }
        RistrettoPoint::vartime_multiscalar_mul(&self.scalars, &self.points)
            == RistrettoPoint::identity()
    }
}

/// A linear relation over committed values: `sum(coeff_i * value_i) == constant`.
///
/// The relation collapses to knowledge of a blinding. Take the product of the
/// commitments raised to their coefficients and divide out `g^constant`: if the
/// relation holds, what is left is a pure power of `h`, so proving it is proving
/// an opening of that residual to the value zero. Nothing about the individual
/// values is revealed, and the verifier reconstructs the same residual from
/// commitments it already holds.
pub fn prove_linear<R: RngCore + CryptoRng>(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitments: &[RistrettoPoint],
    coefficients: &[Scalar],
    blindings: &[Scalar],
    constant: &Scalar,
    rng: &mut R,
) -> OpeningProof {
    let combined: Scalar = coefficients.iter().zip(blindings).map(|(c, r)| c * r).sum();
    let residual = linear_residual(key, commitments, coefficients, constant);
    prove_opening(key, transcript, &residual, &Scalar::ZERO, &combined, rng)
}

pub fn verify_linear(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitments: &[RistrettoPoint],
    coefficients: &[Scalar],
    constant: &Scalar,
    proof: &OpeningProof,
) -> bool {
    let residual = linear_residual(key, commitments, coefficients, constant);
    verify_opening(key, transcript, &residual, proof)
}

fn linear_residual(
    key: &Pedersen,
    commitments: &[RistrettoPoint],
    coefficients: &[Scalar],
    constant: &Scalar,
) -> RistrettoPoint {
    let aggregate = RistrettoPoint::vartime_multiscalar_mul(coefficients, commitments);
    aggregate - key.g * constant
}

/// Knowledge that a commitment opens to 0 or 1, without saying which.
///
/// A Chaum--Pedersen OR: one branch is proved and the other simulated, and the
/// two challenges are forced to sum to the transcript's. `C` is a pure power of
/// `h` in the zero branch and `C - g` is in the one branch, so each branch is
/// an ordinary knowledge-of-exponent proof against `h`.
///
/// A range proof no longer needs this --- `bulletproofs` does that far better
/// than a bit decomposition can --- but a *policy* needs it, because a flag
/// being a flag is not a statement about magnitude and there is nothing audited
/// to defer to.
#[derive(Clone, Debug)]
pub struct BitProof {
    pub t0: RistrettoPoint,
    pub t1: RistrettoPoint,
    pub c0: Scalar,
    pub z0: Scalar,
    pub z1: Scalar,
}

pub fn prove_bit<R: RngCore + CryptoRng>(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitment: &RistrettoPoint,
    bit: bool,
    blinding: &Scalar,
    rng: &mut R,
) -> BitProof {
    let shifted = [*commitment, commitment - key.g];
    let real = usize::from(bit);
    let fake = 1 - real;

    let k = Scalar::random(rng);
    let t_real = key.h * k;
    let c_fake = Scalar::random(rng);
    let z_fake = Scalar::random(rng);
    let t_fake = key.h * z_fake - shifted[fake] * c_fake;

    let (t0, t1) = if bit {
        (t_fake, t_real)
    } else {
        (t_real, t_fake)
    };
    let total = bit_challenge(transcript, commitment, &t0, &t1);
    let c_real = total - c_fake;
    let z_real = k + c_real * blinding;

    if bit {
        BitProof {
            t0,
            t1,
            c0: c_fake,
            z0: z_fake,
            z1: z_real,
        }
    } else {
        BitProof {
            t0,
            t1,
            c0: c_real,
            z0: z_real,
            z1: z_fake,
        }
    }
}

pub fn verify_bit(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitment: &RistrettoPoint,
    proof: &BitProof,
) -> bool {
    let total = bit_challenge(transcript, commitment, &proof.t0, &proof.t1);
    let c1 = total - proof.c0;
    let zero_ok = key.h * proof.z0 == proof.t0 + commitment * proof.c0;
    let one_ok = key.h * proof.z1 == proof.t1 + (commitment - key.g) * c1;
    zero_ok && one_ok
}

fn bit_challenge(
    transcript: &mut Transcript,
    commitment: &RistrettoPoint,
    t0: &RistrettoPoint,
    t1: &RistrettoPoint,
) -> Scalar {
    transcript.append_message(b"dom", b"qomm/bit");
    transcript.append_point(b"C", commitment);
    transcript.append_point(b"T0", t0);
    transcript.append_point(b"T1", t1);
    transcript.challenge_scalar(b"c")
}
