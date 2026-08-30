//! Half-to-even rounding for reproducible measurement contracts.
//!
//! Rust's `f64::round` is half away from zero. This explicit implementation
//! avoids host-language defaults changing an experiment. It sits in the leaf
//! crate because rounding is not simulation, and the harness also needs it for
//! measurements that never build a market.

/// Round to the nearest integer and resolve exact halves toward the even value.
pub fn round_half_even(v: f64) -> i64 {
    let floor = v.floor();
    let diff = v - floor;
    let round_up = diff > 0.5 || (diff == 0.5 && (floor as i64) % 2 != 0);
    let n = if round_up { floor + 1.0 } else { floor };
    n as i64
}
