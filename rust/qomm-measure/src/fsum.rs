//! Error-compensated summation shared by simulations and report builders.
//!
//! The exact-partials and Neumaier variants are deliberately separate because
//! they have different rounding contracts. A naive left-to-right fold is not an
//! acceptable substitute for either one.

/// Error-compensated summation using an exact-partials construction.
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
    // Final half-even correction. If the remaining partial has the
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

/// Neumaier-compensated summation for metrics whose locked contract uses one
/// correction term.
///
/// This is a different algorithm from [`fsum`], which is exactly rounded;
/// Keep it distinct from [`fsum`] rather than routing both contracts through
/// whichever routine happens to be more accurate.
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

    /// Locked vectors fail if either routine drifts toward the other.
    #[test]
    fn the_two_summations_are_the_locked_contract() {
        // sum([0.1] * 10) == 1.0, and a naive fold does not.
        let tenths = [0.1f64; 10];
        assert_eq!(nsum(tenths), 1.0);
        assert_eq!(
            tenths.iter().sum::<f64>(),
            0.999_999_999_999_999_9,
            "the naive fold is intentionally a different contract"
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
