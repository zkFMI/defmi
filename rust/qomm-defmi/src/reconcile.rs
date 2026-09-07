//! Agreeing with the book of record without opening anything to it.
//!
//! Under a book-entry regime this ledger cannot *be* the register: title rests
//! on the record the transfer agent and the account management institutions
//! keep. So it is a mirror, and reconciliation is not a feature but the price
//! of that arrangement.
//!
//! The whole mechanism is one line of algebra. Balances are commitments, and
//! commitments add:
//!
//! ```text
//! sum_i C_i  =  A_a^{sum_i v_i} . h^{sum_i r_i}
//! ```
//!
//! The register says the account holds `N`. Take `A_a * N` off the sum and what
//! is left must be a pure multiple of `h`; proving knowledge of that exponent
//! proves `sum v_i = N` and says nothing else. No individual balance opens, and
//! `N` was the register's own number, so **the proof discloses nothing that was
//! not already on both sides**.
//!
//! Three things follow that are worth saying before the code.
//!
//! **Nobody holds the aggregate blinding.** Each holder has its own. Either the
//! account management institution holds them --- it already holds the mapping
//! from handle to book-entry account, so it is the party that can --- or a
//! quorum assembles the proof without reconstructing the sum.
//!
//! **A break is pass or fail and nothing more.** If the totals disagree the
//! proof cannot be produced, and that is all anyone learns. Finding *where*
//! means opening subtotals, and every subtotal opened is disclosure the design
//! otherwise refuses. [`locate_break`] bisects, so it costs about `2 log2(n)`
//! sub-proofs --- and it reports every range it made public, because the count
//! is the price.
//!
//! **The note rail needs no special case.** A note publishes its value
//! commitment separately from its one-time point, so the product over the
//! unspent notes has the same shape as the sum over accounts. What it cannot do
//! is reconcile one *holder*: there are no accounts to sum over, so a
//! per-holder figure needs the holder, or its view key.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{prove_zero_opening, verify_zero_opening, OpeningProof};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

pub const RECONCILE_DOMAIN: &[u8] = b"QOMM:DEFMI:RECONCILE:v1";

/// What the authoritative ledger says, and who said it.
///
/// Carried rather than passed loose, because reconciling against a number
/// somebody typed is not reconciling. The signature is optional here and is not
/// optional in a deployment: without one, the check says the ledger agrees with
/// whatever it was handed.
#[derive(Clone)]
pub struct Attestation {
    pub register: String,
    pub account: String,
    pub asset: String,
    pub total: u64,
    pub as_of: String,
    pub signature: Option<Signature>,
}

impl Attestation {
    pub fn body(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(RECONCILE_DOMAIN);
        for part in [
            self.register.as_bytes(),
            self.account.as_bytes(),
            self.asset.as_bytes(),
            self.as_of.as_bytes(),
        ] {
            hasher.update((part.len() as u32).to_be_bytes());
            hasher.update(part);
        }
        hasher.update(self.total.to_be_bytes());
        hasher.finalize().into()
    }

    fn transcript(&self) -> Transcript {
        let mut t = Transcript::new(b"qomm:defmi:reconcile");
        t.append_message(b"attestation", &self.body());
        t
    }
}

/// One statement that a set of committed balances sums to a stated total.
pub struct Reconciliation {
    pub attestation: Attestation,
    pub positions: usize,
    pub proof: OpeningProof,
}

/// The sum, which is a commitment to the total by construction.
///
/// Added rather than multiscalar-multiplied. Every coefficient here is one, and
/// asking a multiscalar routine to multiply by one is asking it for a full
/// four times the cost, until it was measured.
pub fn aggregate(commitments: &[RistrettoPoint]) -> RistrettoPoint {
    commitments
        .iter()
        .fold(RistrettoPoint::identity(), |acc, c| acc + c)
}

fn residual(key: &Pedersen, commitments: &[RistrettoPoint], total: u64) -> RistrettoPoint {
    aggregate(commitments) - key.g * Scalar::from(total)
}

/// Show the committed balances sum to the register's figure.
///
/// `key` must carry the asset tag the balances are committed under. A
/// base-generator key would take the total off under the wrong generator and
/// the proof simply would not verify, which is the right failure.
pub fn prove<R: RngCore + CryptoRng>(
    key: &Pedersen,
    commitments: &[RistrettoPoint],
    blindings: &[Scalar],
    attestation: &Attestation,
    rng: &mut R,
) -> Result<Reconciliation, &'static str> {
    if commitments.len() != blindings.len() {
        return Err("a blinding per commitment, or the sum is not the sum");
    }
    let combined: Scalar = blindings.iter().sum();
    let point = residual(key, commitments, attestation.total);
    let mut transcript = attestation.transcript();
    // The residual must be a pure power of h. A general opening proof of it is
    // satisfiable for any total by whoever holds the blindings.
    let proof = prove_zero_opening(key, &mut transcript, &point, &combined, rng);
    Ok(Reconciliation {
        attestation: attestation.clone(),
        positions: commitments.len(),
        proof,
    })
}

/// Whether this ledger agrees with the register, and why not when it does not.
pub fn check(
    key: &Pedersen,
    commitments: &[RistrettoPoint],
    reconciliation: &Reconciliation,
    registrar: Option<&VerifyingKey>,
) -> Result<(), String> {
    if commitments.len() != reconciliation.positions {
        return Err(format!(
            "reconciliation covers {} positions and {} were offered",
            reconciliation.positions,
            commitments.len()
        ));
    }
    let attestation = &reconciliation.attestation;
    match (registrar, &attestation.signature) {
        (Some(key), Some(signature)) => key
            .verify(&attestation.body(), signature)
            .map_err(|_| "the attestation is not signed by that registrar")?,
        (Some(_), None) => return Err("that registrar signed nothing here".into()),
        (None, Some(_)) => {
            return Err("an attestation carries a signature and no \
                                       registrar key was given to check it"
                .into())
        }
        (None, None) => {}
    }
    let point = residual(key, commitments, attestation.total);
    let mut transcript = attestation.transcript();
    if !verify_zero_opening(key, &mut transcript, &point, &reconciliation.proof) {
        return Err(format!(
            "the committed balances do not sum to {}: a break, \
                            and this says nothing about where",
            attestation.total
        ));
    }
    Ok(())
}

/// Which positions do not hold what the register says they hold.
///
/// The level above [`prove`]: an account management institution holds a figure
/// per customer, not one for the account, so it can reconcile position by
/// position and a break localises for free. It needs the openings, which is
/// exactly the party that has them. Nothing is disclosed to anybody else by
/// running it --- it is arithmetic on numbers the runner already holds.
pub fn check_positions<R: RngCore + CryptoRng>(
    key: &Pedersen,
    commitments: &[RistrettoPoint],
    blindings: &[Scalar],
    expected: &[u64],
    rng: &mut R,
) -> Vec<usize> {
    if positions_agree(key, commitments, blindings, expected, rng) {
        return Vec::new();
    }
    // Only now is it worth paying a commitment a position, and only to say
    // which ones. Naming them is the slow half and it runs on the day
    // something is wrong, not on every close.
    commitments
        .iter()
        .zip(blindings)
        .zip(expected)
        .enumerate()
        .filter(|(_, ((c, r), v))| key.commit_u64(**v, r) != **c)
        .map(|(i, _)| i)
        .collect()
}

/// Whether every position holds what it should, in one multiscalar.
///
/// A random linear combination: `sum rho_i (C_i - g v_i - h r_i)` is the
/// identity exactly when every term is, except with probability `1/l`. The
/// naive form recomputes a commitment a position, which is two scalar
/// multiplications each and was 295 ms over 4,096 positions; this is one
/// multiscalar over the same points and Pippenger amortises it.
///
/// It says *whether*, never *which* --- which is the right split, because the
/// common case at a close is that nothing is wrong and nobody needs a list.
pub fn positions_agree<R: RngCore + CryptoRng>(
    key: &Pedersen,
    commitments: &[RistrettoPoint],
    blindings: &[Scalar],
    expected: &[u64],
    rng: &mut R,
) -> bool {
    if commitments.len() != blindings.len() || commitments.len() != expected.len() {
        return false;
    }
    let weights: Vec<Scalar> = (0..commitments.len())
        .map(|_| Scalar::random(rng))
        .collect();
    let value_sum: Scalar = weights
        .iter()
        .zip(expected)
        .map(|(w, v)| w * Scalar::from(*v))
        .sum();
    let blinding_sum: Scalar = weights.iter().zip(blindings).map(|(w, r)| w * r).sum();
    let combined = RistrettoPoint::vartime_multiscalar_mul(&weights, commitments);
    combined == key.g * value_sum + key.h * blinding_sum
}

/// Where the disagreement is, and how much became public in finding it.
#[derive(Debug)]
pub struct BreakSearch {
    pub found: Vec<usize>,
    pub proofs: usize,
    pub ranges_made_public: Vec<(usize, usize, u64)>,
}

impl BreakSearch {
    /// The count is the price, so it is reported rather than absorbed.
    pub fn narrowest(&self) -> usize {
        self.ranges_made_public
            .iter()
            .map(|(l, h, _)| h - l)
            .min()
            .unwrap_or(0)
    }
}

/// Bisect to the positions that do not add up, one sub-proof a step.
///
/// `claimed` is the register answering "what should positions `[low, high)`
/// total". A register that holds only one figure cannot answer it, and then a
/// break stays pass-or-fail: **there is nothing here that finds a break without
/// somebody claiming subtotals**, and pretending otherwise would be the
/// useful-looking lie in this module.
///
/// What it costs is the point. Each step publishes a sub-total, and a sub-total
/// over one position is a balance.
pub fn locate_break<R: RngCore + CryptoRng, F>(
    key: &Pedersen,
    commitments: &[RistrettoPoint],
    blindings: &[Scalar],
    claimed: F,
    expected: u64,
    rng: &mut R,
) -> Result<BreakSearch, String>
where
    F: Fn(usize, usize) -> Option<u64>,
{
    let mut search = BreakSearch {
        found: Vec::new(),
        proofs: 0,
        ranges_made_public: Vec::new(),
    };
    if commitments.is_empty() {
        return Ok(search);
    }
    let mut stack = vec![(0usize, commitments.len(), expected)];
    while let Some((low, high, total)) = stack.pop() {
        search.ranges_made_public.push((low, high, total));
        let attestation = Attestation {
            register: "sub-range".into(),
            account: format!("[{low},{high})"),
            asset: String::new(),
            total,
            as_of: String::new(),
            signature: None,
        };
        let slice = &commitments[low..high];
        let reconciliation = prove(key, slice, &blindings[low..high], &attestation, rng)
            .map_err(|e| e.to_string())?;
        search.proofs += 1;
        if check(key, slice, &reconciliation, None).is_ok() {
            continue;
        }
        if high - low == 1 {
            search.found.push(low);
            continue;
        }
        let middle = (low + high) / 2;
        let mut halves = Vec::with_capacity(2);
        for (a, b) in [(low, middle), (middle, high)] {
            let sub = claimed(a, b).ok_or_else(|| {
                format!(
                    "this register cannot say what [{a},{b}) should total, so the \
                 break stays pass-or-fail"
                )
            })?;
            halves.push((a, b, sub));
        }
        // The halves have to come to the whole they were split from.
        //
        // Without this a register can answer each half with what the ledger
        // actually holds rather than what it attested: both halves check out
        // against their own commitments, the parent still disagrees with the
        // attested total, and the search ends having found nothing. That is
        // worse than the pass-or-fail it replaced --- pass-or-fail at least
        // says there is a break, and this said the break was nowhere.
        let summed = halves[0].2.checked_add(halves[1].2);
        if summed != Some(total) {
            let (l0, h0, s0) = halves[0];
            let (l1, h1, s1) = halves[1];
            return Err(format!(
                "this register says [{l0},{h0}) is {s0} and [{l1},{h1}) is {s1}, \
                 which do not add up to the {total} it says [{low},{high}) is; \
                 the break is in its own figures"
            ));
        }
        for half in halves.into_iter().rev() {
            stack.push(half);
        }
    }
    search.found.sort_unstable();
    Ok(search)
}

/// The sum with arbitrary coefficients, for a caller that needs one.
///
/// Kept separate from [`aggregate`] so the all-ones case --- which is what
/// reconciliation is --- does not pay for generality it never uses.
pub fn weighted(commitments: &[RistrettoPoint], coefficients: &[Scalar]) -> RistrettoPoint {
    RistrettoPoint::vartime_multiscalar_mul(coefficients, commitments)
}
