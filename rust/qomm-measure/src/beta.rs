//! Incomplete-beta numerics shared by audit and measurement code.
//!
//! `beta_ppf` and the Lanczos `lgamma` behind it are not simulation: they are the
//! inverse incomplete beta a Clopper--Pearson bound needs, and they were living
//! in `qomm-sim` only because the DP audit was the first thing to want them.
//! `qomm-harness` wanted them too, and a repository that publishes a proof
//! runner should not have to ship a market simulator to get a confidence
//! interval.

extern "C" {
    #[link_name = "log"]
    fn c_log(x: f64) -> f64;
    #[link_name = "exp"]
    fn c_exp(x: f64) -> f64;
    #[link_name = "lgamma"]
    fn c_lgamma(x: f64) -> f64;
}

/// Platform logarithm shared by every audit calculation.
pub fn ln(x: f64) -> f64 {
    // SAFETY: `log` has no pointer or ownership preconditions.
    unsafe { c_log(x) }
}

fn exp(x: f64) -> f64 {
    // SAFETY: `exp` has no pointer or ownership preconditions.
    unsafe { c_exp(x) }
}

/// Inverse regularised incomplete beta by bisection --- no numerical dependency,
/// and the accuracy a confidence bound needs is well inside what bisection gives.
/// Inverse regularised incomplete beta used by the small-sample harnesses.
///
/// This is public so artifact producers use the same numerics as the DP audit
/// instead of growing a second implementation of the quantile.
pub fn beta_ppf(alpha: f64, a: f64, b: f64) -> f64 {
    if a <= 0.0 {
        return 0.0;
    }
    if b <= 0.0 {
        return 1.0;
    }
    let (mut lo, mut hi) = (0.0f64, 1.0f64);
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if betainc(a, b, mid) < alpha {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    0.5 * (lo + hi)
}

fn ln_gamma(x: f64) -> f64 {
    debug_assert!(x > 0.0, "beta shapes must be positive");
    // SAFETY: `lgamma` has no pointer or ownership preconditions.
    unsafe { c_lgamma(x) }
}

/// Regularised incomplete beta via the continued fraction.
pub fn betainc_public(a: f64, b: f64, x: f64) -> f64 {
    betainc(a, b, x)
}

fn betainc(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let lbeta = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b);
    let front = exp(lbeta + a * ln(x) + b * ln(1.0 - x));
    if x < (a + 1.0) / (a + b + 2.0) {
        front * betacf(a, b, x) / a
    } else {
        1.0 - exp(ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + b * ln(1.0 - x) + a * ln(x))
            * betacf(b, a, 1.0 - x)
            / b
    }
}

fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const TINY: f64 = 1e-30;
    let (qab, qap, qam) = (a + b, a + 1.0, a - 1.0);
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < TINY {
        d = TINY;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=200 {
        let m = m as f64;
        let m2 = 2.0 * m;
        let mut aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        h *= d * c;
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = 1.0 + aa / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < 1e-12 {
            break;
        }
    }
    h
}
