//! published runs.
use qomm_sim::deterministic_random::DeterministicRng;

fn main() {
    let mut rng = DeterministicRng::new(20_260_818);
    let mut mid = 100_000.0f64;
    let mut out = Vec::with_capacity(48_000);
    for _ in 0..48_000 {
        mid += rng.gauss(0.0, 6.0);
        out.push(banker(mid).to_string());
    }
    println!("{}", out.join(" "));
}

fn banker(v: f64) -> i64 {
    let floor = v.floor();
    let diff = v - floor;
    let round_up = diff > 0.5 || (diff == 0.5 && (floor as i64) % 2 != 0);
    let n = if round_up { floor + 1.0 } else { floor };
    n as i64
}
