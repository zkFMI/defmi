//! Interval arithmetic over the values a rule can produce.
//!
//! Every bound a rule needs — the width the circuit must carry, the size of each
//! range proof — falls out of propagating declared bounds through the
//! expression. Doing it in the checker rather than by hand is what makes the
//! audit a compiler output instead of a document.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    pub lo: i128,
    pub hi: i128,
}

impl Interval {
    pub fn new(lo: i128, hi: i128) -> Result<Self, RuleError> {
        if lo > hi {
            return Err(RuleError(format!("empty interval [{lo}, {hi}]")));
        }
        Ok(Interval { lo, hi })
    }

    pub fn point(value: i128) -> Self {
        Interval {
            lo: value,
            hi: value,
        }
    }

    pub fn is_condition(&self) -> bool {
        self.lo == 0 && self.hi == 1
    }

    pub fn plus(self, other: Self) -> Self {
        Interval {
            lo: self.lo + other.lo,
            hi: self.hi + other.hi,
        }
    }

    pub fn minus(self, other: Self) -> Self {
        Interval {
            lo: self.lo - other.hi,
            hi: self.hi - other.lo,
        }
    }

    pub fn times(self, other: Self) -> Self {
        let corners = [
            self.lo * other.lo,
            self.lo * other.hi,
            self.hi * other.lo,
            self.hi * other.hi,
        ];
        Interval {
            lo: *corners.iter().min().unwrap(),
            hi: *corners.iter().max().unwrap(),
        }
    }

    pub fn negated(self) -> Self {
        Interval {
            lo: -self.hi,
            hi: -self.lo,
        }
    }

    pub fn union(self, other: Self) -> Self {
        Interval {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }

    /// Signed bit width that holds every value in the interval.
    pub fn width_bits(&self) -> u32 {
        let magnitude = self.lo.unsigned_abs().max(self.hi.unsigned_abs());
        (128 - magnitude.leading_zeros() + 1).max(2)
    }
}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.lo, self.hi)
    }
}

/// Every rejection names its exact reason: a rule that is refused should tell
/// its author what to change, not that something was wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError(pub String);

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RuleError {}
