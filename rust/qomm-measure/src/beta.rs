//! CPython's numerics, kept where anything can reach them.
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
}

/// The platform `log`, which is the one CPython's `math.log` calls. Public
/// because the DP audit takes a logarithm of a ratio of these bounds and has to
/// take the same one.
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

// Adapted from CPython 3.13.5 `Modules/mathmodule.c` under the PSF License 2.0:
// https://github.com/python/cpython/blob/v3.13.5/Modules/mathmodule.c
//
// CPython deliberately does not use platform `lgamma` on macOS. Matching this
// rational Lanczos form is necessary for value-identical audit JSON.
const LANCZOS_G: f64 = 6.024_680_040_776_729_583_740_234_375;
const LANCZOS_NUM: [f64; 13] = [
    23_531_376_880.410_759_688_572_007_674_451_636_754_734_846_804_940,
    42_919_803_642.649_098_768_957_899_047_001_988_850_926_355_848_959,
    35_711_959_237.355_668_049_440_185_451_547_166_705_960_488_635_843,
    17_921_034_426.037_209_699_919_755_754_458_931_112_671_403_265_390,
    6_039_542_586.352_028_005_064_291_644_307_297_921_069_938_842_070_8,
    1_439_720_407.311_721_673_663_223_072_794_912_393_971_548_578_677_2,
    248_874_557.862_054_156_511_460_386_413_229_423_216_321_251_278_01,
    31_426_415.585_400_194_380_614_231_628_318_205_362_874_684_987_640,
    2_876_370.628_935_372_441_225_409_051_620_849_613_599_114_537_876_8,
    186_056.265_395_223_495_040_294_989_716_045_699_282_207_842_363_28,
    8_071.672_002_365_816_210_638_002_902_272_250_613_821_851_632_502_4,
    210.824_277_751_579_345_872_509_733_920_713_362_711_669_695_802_91,
    2.506_628_274_631_000_270_164_908_177_133_837_338_626_431_079_340_8,
];
const LANCZOS_DEN: [f64; 13] = [
    0.0,
    39_916_800.0,
    120_543_840.0,
    150_917_976.0,
    105_258_076.0,
    45_995_730.0,
    13_339_535.0,
    2_637_558.0,
    357_423.0,
    32_670.0,
    1_925.0,
    66.0,
    1.0,
];

fn lanczos_sum(x: f64) -> f64 {
    let (mut numerator, mut denominator) = (0.0, 0.0);
    if x < 5.0 {
        for index in (0..LANCZOS_NUM.len()).rev() {
            numerator = numerator * x + LANCZOS_NUM[index];
            denominator = denominator * x + LANCZOS_DEN[index];
        }
    } else {
        for index in 0..LANCZOS_NUM.len() {
            numerator = numerator / x + LANCZOS_NUM[index];
            denominator = denominator / x + LANCZOS_DEN[index];
        }
    }
    numerator / denominator
}

fn ln_gamma(x: f64) -> f64 {
    debug_assert!(
        x > 0.0,
        "the incomplete beta function requires positive shapes"
    );
    if x == x.floor() && x <= 2.0 {
        return 0.0;
    }
    if x < 1e-20 {
        return -ln(x);
    }
    let mut result = ln(lanczos_sum(x)) - LANCZOS_G;
    // CPython's C build contracts this multiply-add; spelling it explicitly
    // preserves the installed interpreter's last bit in release and debug.
    result = (x - 0.5).mul_add(ln(x + LANCZOS_G - 0.5) - 1.0, result);
    result
}

/// Regularised incomplete beta via the continued fraction.
/// Exposed so the port can be diffed against the Python it replaces.
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

