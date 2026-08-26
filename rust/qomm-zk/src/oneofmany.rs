//! Groth--Kohlweiss: one commitment in a set opens to zero, without saying
//! which.
//!
//! No audited crate implements this, so it is written here. It does two jobs in
//! this system: proving that a blinded asset tag is one of the registered ones
//! when a balance is issued, and proving that a spend consumes one of the notes
//! in a ring without naming it.
//!
//! The verifier is where the port pays. In Python it was O(N) separate scalar
//! multiplications; here the whole O(N) term is one multiscalar multiplication,
//! and the per-bit checks join the same batch as everything else.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use crate::pedersen::Pedersen;
use crate::sigma::TranscriptExt;

#[derive(Clone, Debug)]
pub struct GkProof {
    pub cl: Vec<RistrettoPoint>,
    pub ca: Vec<RistrettoPoint>,
    pub cb: Vec<RistrettoPoint>,
    pub gk: Vec<RistrettoPoint>,
    pub f: Vec<Scalar>,
    pub za: Vec<Scalar>,
    pub zb: Vec<Scalar>,
    pub zd: Scalar,
}

impl GkProof {
    /// Compressed points are 32 bytes and scalars are 32 bytes, so the size is
    /// exact rather than an estimate.
    pub fn size_bytes(&self) -> usize {
        32 * (self.cl.len() + self.ca.len() + self.cb.len() + self.gk.len())
            + 32 * (self.f.len() + self.za.len() + self.zb.len() + 1)
    }
}

fn challenge(
    transcript: &mut Transcript,
    commitments: &[RistrettoPoint],
    cl: &[RistrettoPoint],
    ca: &[RistrettoPoint],
    cb: &[RistrettoPoint],
    gk: &[RistrettoPoint],
) -> Scalar {
    transcript.append_message(b"dom", b"qomm/gk");
    // The set the proof is *about* goes in first. It used not to, and the
    // commitments then entered only through the final weighted sum
    // `sum_i p_i(x) C_i` --- so an attacker could move mass between two members
    // and leave that sum where it was: pick j and k with `p_k != 0`, add D to
    // C_j and subtract `(p_j/p_k) D` from C_k. The challenge did not depend on
    // the set, so it did not move either, and a proof about one set verified
    // against a set its prover had no witness in.
    //
    // Callers could bind the set in their own transcript and `vetting.rs`
    // does. Relying on every caller to remember is the wrong place for the
    // requirement: the proof is a statement about this set, so this is where
    // the set belongs.
    for (label, set) in [
        (&b"C"[..], commitments),
        (&b"cl"[..], cl),
        (&b"ca"[..], ca),
        (&b"cb"[..], cb),
        (&b"gk"[..], gk),
    ] {
        transcript.append_u64(b"n", set.len() as u64);
        for point in set {
            transcript.append_message(label, point.compress().as_bytes());
        }
    }
    transcript.challenge_scalar(b"x")
}

/// The challenge a verifier will derive, for a test that needs to predict it.
#[doc(hidden)]
pub fn challenge_for(
    transcript: &mut Transcript,
    commitments: &[RistrettoPoint],
    proof: &GkProof,
) -> Scalar {
    challenge(
        transcript,
        commitments,
        &proof.cl,
        &proof.ca,
        &proof.cb,
        &proof.gk,
    )
}

/// Coefficients of `p_i(x) = prod_j f_{j, i_j}` as a polynomial in x.
///
/// `f_{j,1} = l_j x + a_j` and `f_{j,0} = (1 - l_j) x - a_j`, so each factor is
/// linear and the product is a convolution. This is the O(N log N) part.
fn poly_coefficients(index: usize, bits: usize, a: &[Scalar], ell: &[Scalar]) -> Vec<Scalar> {
    let mut poly = vec![Scalar::ONE];
    for j in 0..bits {
        let linear = if (index >> j) & 1 == 1 {
            [a[j], ell[j]]
        } else {
            [-a[j], Scalar::ONE - ell[j]]
        };
        let mut product = vec![Scalar::ZERO; poly.len() + 1];
        for (p, coefficient) in poly.iter().enumerate() {
            product[p] += coefficient * linear[0];
            product[p + 1] += coefficient * linear[1];
        }
        poly = product;
    }
    poly
}

pub fn prove<R: RngCore + CryptoRng>(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitments: &[RistrettoPoint],
    index: usize,
    randomness: &Scalar,
    rng: &mut R,
) -> Result<GkProof, &'static str> {
    let size = commitments.len();
    if !size.is_power_of_two() || size < 2 {
        return Err("the set must be a power of two, at least two");
    }
    if index >= size {
        return Err("the index is outside the set");
    }
    let bits = size.trailing_zeros() as usize;

    let ell: Vec<Scalar> = (0..bits)
        .map(|j| {
            if (index >> j) & 1 == 1 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            }
        })
        .collect();
    let a: Vec<Scalar> = (0..bits).map(|_| Scalar::random(rng)).collect();
    let r: Vec<Scalar> = (0..bits).map(|_| Scalar::random(rng)).collect();
    let s: Vec<Scalar> = (0..bits).map(|_| Scalar::random(rng)).collect();
    let t: Vec<Scalar> = (0..bits).map(|_| Scalar::random(rng)).collect();

    let cl: Vec<_> = (0..bits).map(|j| key.commit(&ell[j], &r[j])).collect();
    let ca: Vec<_> = (0..bits).map(|j| key.commit(&a[j], &s[j])).collect();
    let cb: Vec<_> = (0..bits)
        .map(|j| key.commit(&(ell[j] * a[j]), &t[j]))
        .collect();

    let coefficients: Vec<Vec<Scalar>> = (0..size)
        .map(|i| poly_coefficients(i, bits, &a, &ell))
        .collect();

    let rho: Vec<Scalar> = (0..bits).map(|_| Scalar::random(rng)).collect();
    let gk: Vec<RistrettoPoint> = (0..bits)
        .map(|k| {
            let scalars: Vec<Scalar> = coefficients.iter().map(|c| c[k]).collect();
            RistrettoPoint::vartime_multiscalar_mul(&scalars, commitments) + key.h * rho[k]
        })
        .collect();

    let x = challenge(transcript, commitments, &cl, &ca, &cb, &gk);
    let f: Vec<Scalar> = (0..bits).map(|j| ell[j] * x + a[j]).collect();
    let za: Vec<Scalar> = (0..bits).map(|j| r[j] * x + s[j]).collect();
    let zb: Vec<Scalar> = (0..bits).map(|j| r[j] * (x - f[j]) + t[j]).collect();

    let mut x_to_bits = Scalar::ONE;
    for _ in 0..bits {
        x_to_bits *= x;
    }
    let mut zd = randomness * x_to_bits;
    let mut x_k = Scalar::ONE;
    for rho_k in rho.iter() {
        zd -= rho_k * x_k;
        x_k *= x;
    }
    Ok(GkProof {
        cl,
        ca,
        cb,
        gk,
        f,
        za,
        zb,
        zd,
    })
}

pub fn verify(
    key: &Pedersen,
    transcript: &mut Transcript,
    commitments: &[RistrettoPoint],
    proof: &GkProof,
) -> bool {
    let size = commitments.len();
    if !size.is_power_of_two() || size < 2 {
        return false;
    }
    let bits = size.trailing_zeros() as usize;
    if proof.f.len() != bits
        || proof.cl.len() != bits
        || proof.ca.len() != bits
        || proof.cb.len() != bits
        || proof.gk.len() != bits
        || proof.za.len() != bits
        || proof.zb.len() != bits
    {
        return false;
    }
    let x = challenge(
        transcript,
        commitments,
        &proof.cl,
        &proof.ca,
        &proof.cb,
        &proof.gk,
    );

    for j in 0..bits {
        if key.commit(&proof.f[j], &proof.za[j]) != proof.cl[j] * x + proof.ca[j] {
            return false;
        }
        if key.commit(&Scalar::ZERO, &proof.zb[j]) != proof.cl[j] * (x - proof.f[j]) + proof.cb[j] {
            return false;
        }
    }

    // The O(N) term, as one multiscalar multiplication rather than N of them.
    let mut scalars: Vec<Scalar> = Vec::with_capacity(size + bits + 1);
    let mut points: Vec<RistrettoPoint> = Vec::with_capacity(size + bits + 1);
    for (i, commitment) in commitments.iter().enumerate() {
        let mut value = Scalar::ONE;
        for j in 0..bits {
            value *= if (i >> j) & 1 == 1 {
                proof.f[j]
            } else {
                x - proof.f[j]
            };
        }
        scalars.push(value);
        points.push(*commitment);
    }
    let mut x_k = Scalar::ONE;
    for gk in proof.gk.iter() {
        scalars.push(-x_k);
        points.push(*gk);
        x_k *= x;
    }
    scalars.push(-proof.zd);
    points.push(key.h);
    RistrettoPoint::vartime_multiscalar_mul(&scalars, &points) == RistrettoPoint::identity()
}
