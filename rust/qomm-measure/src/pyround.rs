//! Python's rounding mode, which is not Rust's.
//!
//! `f64::round` is half away from zero and Python's `round` is half to even.
//! Every place a port rounds, this is what the original meant. It sits in the
//! leaf crate because rounding is not simulation, and the harness needs it for
//! measurements that never build a market.

/// Python's `round` is half-to-even and Rust's is half-away-from-zero. Every
/// place the original rounds, this is what it meant.
pub fn py_round(v: f64) -> i64 {
    let floor = v.floor();
    let diff = v - floor;
    let round_up = diff > 0.5 || (diff == 0.5 && (floor as i64) % 2 != 0);
    let n = if round_up { floor + 1.0 } else { floor };
    n as i64
}
