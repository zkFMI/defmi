//! The confidence bound the epsilon audit rests on, checked against the Python
//! it replaces and against the cases where a bound is easy to get wrong.

use qomm_sim::audit::{betainc_public, clopper_pearson};

fn close(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() < tol
}

#[test]
fn the_interval_matches_the_python_to_twelve_decimals() {
    for (k, n, lo, hi) in [
        (0usize, 100usize, 0.0, 0.036_216_692_645),
        (5, 100, 0.016_431_879_182, 0.112_834_911_105),
        (50, 100, 0.398_321_129_503, 0.601_678_870_497),
        (95, 100, 0.887_165_088_895, 0.983_568_120_818),
        (100, 100, 0.963_783_307_355, 1.0),
        (12, 4_000, 0.001_551_074_854, 0.005_234_526_286),
    ] {
        let (l, h) = clopper_pearson(k, n, 0.05);
        assert!(close(l, lo, 1e-11), "{k}/{n} lower {l}");
        assert!(close(h, hi, 1e-11), "{k}/{n} upper {h}");
    }
}

#[test]
fn the_endpoints_are_exact_rather_than_nearly_exact() {
    // Zero successes must give a lower bound of exactly zero, and n successes an
    // upper bound of exactly one; a bisection that merely approached them would
    // make a correct mechanism look like a violation.
    assert_eq!(clopper_pearson(0, 100, 0.05).0, 0.0);
    assert_eq!(clopper_pearson(100, 100, 0.05).1, 1.0);
}

#[test]
fn the_incomplete_beta_agrees_with_the_python() {
    assert!(close(betainc_public(2.0, 3.0, 0.4), 0.524_8, 1e-13));
    assert!(close(
        betainc_public(0.5, 0.5, 0.25),
        0.333_333_333_333_32,
        1e-13
    ));
    assert!(close(
        betainc_public(10.0, 20.0, 0.3),
        0.364_004_081_071_94,
        1e-13
    ));
    // Large second argument is where the gamma approximation shows, and it shows
    // in the twelfth decimal.
    assert!(close(
        betainc_public(1.0, 4_000.0, 0.001),
        0.981_720_980_172_44,
        1e-11
    ));
}

#[test]
fn the_interval_widens_as_the_confidence_rises() {
    let (lo95, hi95) = clopper_pearson(50, 100, 0.05);
    let (lo99, hi99) = clopper_pearson(50, 100, 0.01);
    assert!(lo99 < lo95 && hi99 > hi95);
}
