//! Error-compensated summation, shared by everything that has to agree with
//! CPython's `math.fsum` to the last bit.
//!
//! `statistics.fmean` sums with `fsum` and divides once, so a naive Rust sum in
//! the same place lands one unit in the last place away. That showed up as a
//! twenty-three-value disagreement between the two `run_sim_matrix`
//! implementations, all of them correlations, all in the sixteenth significant
//! digit. It lives here rather than in the harness because `attackers` needs it
//! and the harness depends on this crate, not the other way round.

/// Error-compensated summation with the same partials construction used by
/// CPython's `math.fsum` for the finite values these harnesses produce.
pub fn fsum(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut partials: Vec<f64> = Vec::new();
    for mut x in values {
        let old = std::mem::take(&mut partials);
        for mut y in old {
            if x.abs() < y.abs() {
                std::mem::swap(&mut x, &mut y);
            }
            let high = x + y;
            let low = y - (high - x);
            if low != 0.0 {
                partials.push(low);
            }
            x = high;
        }
        partials.push(x);
    }
    let Some(mut high) = partials.pop() else {
        return 0.0;
    };
    let mut low = 0.0;
    while let Some(value) = partials.pop() {
        let before = high;
        high = before + value;
        let rounded = high - before;
        low = value - rounded;
        if low != 0.0 {
            break;
        }
    }
    // CPython's final half-even correction. If the remaining partial has the
    // same sign as the rounding residue, twice the residue may be exactly one
    // representable step and therefore decides the correctly rounded result.
    if partials
        .last()
        .is_some_and(|next| (low < 0.0 && *next < 0.0) || (low > 0.0 && *next > 0.0))
    {
        let doubled = low * 2.0;
        let corrected = high + doubled;
        if corrected - high == doubled {
            high = corrected;
        }
    }
    high
}

/// CPython's builtin `sum` over floats, which is *not* a naive accumulation.
///
/// Since CPython 3.12 `sum()` carries a Neumaier compensation term, so
/// `sum([0.1] * 10)` is exactly `1.0` where a left-to-right fold gives
/// `0.9999999999999999`. Every `sum(...)` over floats in the Python this crate
/// was ported from therefore has compensated semantics, and a Rust
/// `.sum::<f64>()` in the same place does not reproduce them. That difference
/// reached the reported correlations.
///
/// This is a different algorithm from [`fsum`], which is exactly rounded;
/// `statistics.fmean` uses `fsum` and the builtin uses this one, so a port has
/// to keep them apart rather than route both through the more accurate of the
/// two.
pub fn nsum(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut total = 0.0f64;
    let mut compensation = 0.0f64;
    for value in values {
        let sum = total + value;
        compensation += if total.abs() >= value.abs() {
            (total - sum) + value
        } else {
            (value - sum) + total
        };
        total = sum;
    }
    total + compensation
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three values CPython prints for these inputs, typed in from a real
    /// interpreter rather than derived here, so this fails if either routine
    /// drifts towards the other.
    #[test]
    fn the_two_summations_are_the_ones_python_uses() {
        // sum([0.1] * 10) == 1.0, and a naive fold does not.
        let tenths = [0.1f64; 10];
        assert_eq!(nsum(tenths), 1.0);
        assert_eq!(
            tenths.iter().sum::<f64>(),
            0.999_999_999_999_999_9,
            "the naive fold is what the port used to do"
        );
        // math.fsum agrees here; the point of keeping both is the cases below.
        assert_eq!(fsum(tenths), 1.0);

        // sum([1e100, 1.0, -1e100]) == 1.0 under compensation, 0.0 without.
        let cancelling = [1e100f64, 1.0, -1e100];
        assert_eq!(nsum(cancelling), 1.0);
        assert_eq!(fsum(cancelling), 1.0);
        assert_eq!(cancelling.iter().sum::<f64>(), 0.0);

        // And where the two compensated routines part company: Neumaier keeps
        // one correction term, Shewchuk keeps every partial.
        let hard = [1.0f64, 1e16, 1.0, -1e16, 1.0, 1e16, 1.0, -1e16];
        assert_eq!(fsum(hard), 4.0);
        assert_eq!(nsum(hard), 4.0);
    }
}
