//! Shamir sharing, and naming the party whose share does not lie on the polynomial.
//!
//! The decoder belongs beside the commitments rather than beside the MPC runner
//! because the
//! binding chain now deals over the group's scalar field: a share the circuit
//! reads and a scalar a commitment opens to are the same kind of thing, so the
//! decoder is field arithmetic in the field everything else here already uses.
//!
//! # Why a decoder rather than a check
//!
//! Shamir shares of a degree-`t` secret are evaluations of a degree-`t`
//! polynomial, which is a Reed--Solomon codeword `RS[n, t+1]` with minimum
//! distance `n - t`. So up to `floor((n - t - 1) / 2)` wrong shares can be
//! **corrected**, and Berlekamp--Welch returns the error locator polynomial
//! whose roots are the evaluation points of the parties that lied. A protocol
//! that only checks consistency throws away the second half of that.
//!
//! At `n = 7`, `t = 2` the capacity is 2, which is exactly the corruption
//! threshold. A product before degree reduction is degree `2t` and the capacity
//! falls to 1, which is where `n >= 4t + 1` comes from and why nine nodes.
//!
//! # What it cannot see
//!
//! A party that feeds a *different value* rather than a wrong share of the right
//! one. That is a valid sharing of something else, so nothing is inconsistent
//! and there is nothing to decode. The transport binding and circuit input check
//! answer that different question.

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

/// How many wrong shares a codeword of this shape can be corrected through.
pub fn capacity(n: usize, degree: usize) -> usize {
    if n <= degree {
        return 0;
    }
    (n - degree - 1) / 2
}

/// Evaluation points, one per party, starting at one --- zero is the secret.
pub fn points(n: usize) -> Vec<Scalar> {
    (1..=n as u64).map(Scalar::from).collect()
}

fn evaluate(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, c| acc * x + c)
}

/// One share per point, from a random polynomial with the secret at zero.
pub fn share<R: RngCore + CryptoRng>(
    secret: &Scalar,
    degree: usize,
    points: &[Scalar],
    rng: &mut R,
) -> Vec<Scalar> {
    share_with_coefficients(secret, degree, points, rng).0
}

/// Deal one Shamir polynomial and return both its evaluations and coefficients.
///
/// Most callers should use [`share`]. Verifiable secret sharing additionally
/// publishes Pedersen commitments to the coefficients, so its dealer needs the
/// exact polynomial bytes instead of generating a second, unrelated sharing.
pub fn share_with_coefficients<R: RngCore + CryptoRng>(
    secret: &Scalar,
    degree: usize,
    points: &[Scalar],
    rng: &mut R,
) -> (Vec<Scalar>, Vec<Scalar>) {
    let mut coefficients = Vec::with_capacity(degree + 1);
    coefficients.push(*secret);
    for _ in 0..degree {
        coefficients.push(Scalar::random(rng));
    }
    let shares = points.iter().map(|x| evaluate(&coefficients, x)).collect();
    (shares, coefficients)
}

/// Lagrange at zero. What an engine does, and it believes what it is given.
pub fn reconstruct(points: &[Scalar], shares: &[Scalar]) -> Scalar {
    let mut total = Scalar::ZERO;
    for (i, xi) in points.iter().enumerate() {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (j, xj) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator *= -xj;
            denominator *= xi - xj;
        }
        total += shares[i] * numerator * denominator.invert();
    }
    total
}

/// What a decode concluded.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The secret, and which parties sent a share that is not on the polynomial.
    Decoded {
        secret: Scalar,
        culprits: Vec<usize>,
    },
    /// More wrong shares than the code can resolve. Naming any party here would
    /// be naming one at random, which is worse than giving up.
    Beyond { capacity: usize, reason: String },
}

/// Recover the secret and name the parties whose shares do not lie on it.
///
/// The honest path is one interpolation and `n - degree - 1` evaluations: the
/// linear system is only built once a share is known to disagree, because on a
/// protocol's common path nothing does.
pub fn locate(points: &[Scalar], shares: &[Scalar], degree: usize) -> Verdict {
    let n = points.len();
    let capacity = capacity(n, degree);
    if shares.len() != n {
        return Verdict::Beyond {
            capacity,
            reason: format!("{} points and {} shares", n, shares.len()),
        };
    }
    if n < degree + 1 {
        return Verdict::Beyond {
            capacity,
            reason: format!(
                "{n} shares cannot determine a degree-{degree} \
                             polynomial, which needs {}",
                degree + 1
            ),
        };
    }

    // The honest path first: interpolate through the first degree+1 and check
    // the rest against it.
    let secret = reconstruct(&points[..degree + 1], &shares[..degree + 1]);
    let coefficients = interpolate(&points[..degree + 1], &shares[..degree + 1]);
    let disagreeing: Vec<usize> = (degree + 1..n)
        .filter(|i| evaluate(&coefficients, &points[*i]) != shares[*i])
        .collect();
    if disagreeing.is_empty() {
        return Verdict::Decoded {
            secret,
            culprits: Vec::new(),
        };
    }

    for errors in 1..=capacity {
        if let Some(verdict) = welch(points, shares, degree, errors) {
            return verdict;
        }
    }
    Verdict::Beyond {
        capacity,
        reason: format!(
            "more than {capacity} wrong share(s): at n={n} and \
                         degree {degree} the code has distance {}, so this is \
                         beyond what any decoder can resolve",
            n - degree
        ),
    }
}

/// Berlekamp--Welch for exactly `errors` errors, or `None` if there are not that many.
fn welch(points: &[Scalar], shares: &[Scalar], degree: usize, errors: usize) -> Option<Verdict> {
    // Q(x) = E(x) * P(x) with deg E = errors, deg Q <= degree + errors.
    // Unknowns: Q's degree+errors+1 coefficients and E's `errors` (E is monic).
    let n = points.len();
    let q_len = degree + errors + 1;
    let unknowns = q_len + errors;
    let mut matrix = Vec::with_capacity(n);
    let mut rhs = Vec::with_capacity(n);
    for i in 0..n {
        let mut row = Vec::with_capacity(unknowns);
        let mut power = Scalar::ONE;
        for _ in 0..q_len {
            row.push(power);
            power *= points[i];
        }
        // -y_i * E's non-leading coefficients; the leading one is 1 and moves
        // to the right-hand side
        let mut power = Scalar::ONE;
        for _ in 0..errors {
            row.push(-shares[i] * power);
            power *= points[i];
        }
        rhs.push(shares[i] * power);
        matrix.push(row);
    }
    let solution = solve(&mut matrix, &mut rhs, unknowns)?;
    let (q, e_low) = solution.split_at(q_len);
    let mut e: Vec<Scalar> = e_low.to_vec();
    e.push(Scalar::ONE);

    let (p, exact) = divide(q, &e)?;
    if !exact {
        return None;
    }
    // The culprits are the points E vanishes at, found by evaluating rather
    // than by root-finding --- there are only n of them and evaluating is exact.
    let culprits: Vec<usize> = (0..n)
        .filter(|i| evaluate(&e, &points[*i]) == Scalar::ZERO)
        .collect();
    if culprits.len() != errors {
        return None;
    }
    // And a decoded polynomial has to agree with every share that is not a
    // culprit's; a solution that does not is not the codeword.
    for i in 0..n {
        if !culprits.contains(&i) && evaluate(&p, &points[i]) != shares[i] {
            return None;
        }
    }
    Some(Verdict::Decoded {
        secret: *p.first().unwrap_or(&Scalar::ZERO),
        culprits,
    })
}

/// Gaussian elimination with the free variables set to zero.
fn solve(matrix: &mut [Vec<Scalar>], rhs: &mut [Scalar], unknowns: usize) -> Option<Vec<Scalar>> {
    let rows = matrix.len();
    let mut pivot_of = vec![usize::MAX; unknowns];
    let mut row = 0;
    for column in 0..unknowns {
        let Some(found) = (row..rows).find(|r| matrix[*r][column] != Scalar::ZERO) else {
            continue;
        };
        matrix.swap(row, found);
        rhs.swap(row, found);
        let inverse = matrix[row][column].invert();
        for cell in matrix[row].iter_mut().take(unknowns).skip(column) {
            *cell *= inverse;
        }
        rhs[row] *= inverse;
        let pivot_row = matrix[row].clone();
        for (r, matrix_row) in matrix.iter_mut().enumerate() {
            if r == row || matrix_row[column] == Scalar::ZERO {
                continue;
            }
            let factor = matrix_row[column];
            for (c, cell) in matrix_row
                .iter_mut()
                .enumerate()
                .take(unknowns)
                .skip(column)
            {
                let value = pivot_row[c] * factor;
                *cell -= value;
            }
            let value = rhs[row] * factor;
            rhs[r] -= value;
        }
        pivot_of[column] = row;
        row += 1;
        if row == rows {
            break;
        }
    }
    // A row that is all zeros with a non-zero right-hand side has no solution.
    for (r, matrix_row) in matrix.iter().enumerate().take(rows).skip(row) {
        if rhs[r] != Scalar::ZERO && matrix_row.iter().all(|v| *v == Scalar::ZERO) {
            return None;
        }
    }
    Some(
        (0..unknowns)
            .map(|c| {
                if pivot_of[c] == usize::MAX {
                    Scalar::ZERO
                } else {
                    rhs[pivot_of[c]]
                }
            })
            .collect(),
    )
}

/// Polynomial division, and whether it came out exact.
fn divide(numerator: &[Scalar], denominator: &[Scalar]) -> Option<(Vec<Scalar>, bool)> {
    let mut remainder = numerator.to_vec();
    let d = denominator.len() - 1;
    if remainder.len() <= d {
        return Some((
            vec![Scalar::ZERO],
            remainder.iter().all(|v| *v == Scalar::ZERO),
        ));
    }
    let lead = denominator[d].invert();
    let mut quotient = vec![Scalar::ZERO; remainder.len() - d];
    for i in (0..quotient.len()).rev() {
        let factor = remainder[i + d] * lead;
        quotient[i] = factor;
        for j in 0..=d {
            let value = denominator[j] * factor;
            remainder[i + j] -= value;
        }
    }
    let exact = remainder[..d.min(remainder.len())]
        .iter()
        .all(|v| *v == Scalar::ZERO);
    Some((quotient, exact))
}

/// The coefficients of the unique polynomial through these points.
fn interpolate(points: &[Scalar], values: &[Scalar]) -> Vec<Scalar> {
    let mut result = vec![Scalar::ZERO; points.len()];
    for (i, xi) in points.iter().enumerate() {
        // the Lagrange basis polynomial for i, built up by multiplying out
        let mut basis = vec![Scalar::ONE];
        let mut denominator = Scalar::ONE;
        for (j, xj) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let mut next = vec![Scalar::ZERO; basis.len() + 1];
            for (k, b) in basis.iter().enumerate() {
                next[k] -= b * xj;
                next[k + 1] += b;
            }
            basis = next;
            denominator *= xi - xj;
        }
        let scale = values[i] * denominator.invert();
        for (k, b) in basis.iter().enumerate() {
            result[k] += b * scale;
        }
    }
    result
}
