//! One way of reporting a repeated measurement, shared by every benchmark.
//!
//! A bare median says what one number came out and nothing about whether it
//! means anything. Two runs of the same benchmark on one machine have disagreed
//! by half again here, and a reader --- including a later version of us --- cannot
//! tell that from a single figure. So every timing carries how many samples it
//! is made of and how far they spread.
//!
//! Both a mean and a median are kept, deliberately. Timings are right-skewed:
//! one scheduling hiccup pulls the mean and leaves the median alone, so the
//! median is what to compare and the mean is what the standard deviation belongs
//! to. When the two disagree by much, that is itself the finding.
//!
//! Deterministic quantities do not go through this. A proof's byte length and a
//! compiled round count are the same on every run, and dressing them with a
//! standard deviation of zero would claim a measurement nobody made. [`Exact`]
//! marks those so the two kinds cannot be confused downstream.

use std::fmt;
pub mod beta;
pub mod fsum;
pub mod pyrandom;
pub mod pyround;
pub mod hosts;

use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub mean: f64,
    /// Sample standard deviation. `None` for one sample, because a single
    /// observation has no spread --- reporting zero would say the measurement
    /// was stable when it was never repeated.
    pub sd: Option<f64>,
    pub median: f64,
    pub min: f64,
    pub max: f64,
}

impl Summary {
    pub fn of(samples: &[f64]) -> Option<Summary> {
        if samples.is_empty() {
            return None;
        }
        let n = samples.len();
        // `statistics.fmean`, which is `math.fsum` and one division.
        let mean = crate::fsum::fsum(samples.iter().copied()) / n as f64;
        let sd = if n > 1 {
            // Not `statistics.stdev`, which accumulates the sum of squared
            // deviations in exact rational arithmetic and takes one square root
            // at the end. This is the two-pass float estimator, and it can
            // differ from CPython's in the last place. Everything `Summary`
            // describes is a duration, and durations are excluded from the
            // Python-against-Rust comparisons for the obvious reason, so the
            // difference is not observable there --- but it would be if a
            // non-timing value ever reached this.
            let var =
                crate::fsum::fsum(samples.iter().map(|v| (v - mean) * (v - mean))) / (n - 1) as f64;
            Some(var.sqrt())
        } else {
            None
        };
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = if n % 2 == 1 {
            sorted[n / 2]
        } else {
            0.5 * (sorted[n / 2 - 1] + sorted[n / 2])
        };
        Some(Summary {
            n,
            mean,
            sd,
            median,
            min: sorted[0],
            max: sorted[n - 1],
        })
    }

    /// The spread as a fraction of the mean. Above a few percent, the last digit
    /// of the mean is not real.
    pub fn rsd(&self) -> Option<f64> {
        self.sd
            .filter(|_| self.mean != 0.0)
            .map(|sd| sd / self.mean)
    }

    /// Whether this measurement sits below another with daylight between them.
    /// Two means alone will always order themselves, including when the ordering
    /// is noise, so a reported crossover should go through this.
    pub fn below(&self, other: &Summary) -> bool {
        match (self.sd, other.sd) {
            (Some(a), Some(b)) => self.mean + a < other.mean - b,
            _ => self.mean < other.mean,
        }
    }

    pub fn json(&self) -> String {
        let opt = |v: Option<f64>| match v {
            Some(x) => format!("{x:.6}"),
            None => "null".to_string(),
        };
        format!(
            "{{\"n\": {}, \"mean\": {:.6}, \"sd\": {}, \"median\": {:.6}, \
                 \"min\": {:.6}, \"max\": {:.6}, \"rsd\": {}}}",
            self.n,
            self.mean,
            opt(self.sd),
            self.median,
            self.min,
            self.max,
            opt(self.rsd())
        )
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let places = f.precision().unwrap_or(2);
        match self.sd {
            None => write!(f, "{:.*} (n=1)", places, self.mean),
            Some(sd) => write!(
                f,
                "{:.*} ± {:.*} (n={})",
                places, self.mean, places, sd, self.n
            ),
        }
    }
}

/// A quantity that is identical on every run, marked as such.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exact(pub u64);

impl Exact {
    pub fn json(&self) -> String {
        format!("{{\"exact\": {}}}", self.0)
    }
}

impl fmt::Display for Exact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (exact)", self.0)
    }
}

/// Time a closure `repeats` times and summarise, in milliseconds.
pub fn time_ms<F: FnMut()>(repeats: usize, mut body: F) -> Summary {
    sample(repeats, 1e3, &mut body)
}

/// The same in microseconds, for operations too small to read in milliseconds.
pub fn time_us<F: FnMut()>(repeats: usize, mut body: F) -> Summary {
    sample(repeats, 1e6, &mut body)
}

fn sample<F: FnMut()>(repeats: usize, scale: f64, body: &mut F) -> Summary {
    let mut samples = Vec::with_capacity(repeats.max(1));
    for _ in 0..repeats.max(1) {
        let start = Instant::now();
        body();
        samples.push(start.elapsed().as_secs_f64() * scale);
    }
    Summary::of(&samples).expect("at least one repeat")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_sample_has_no_spread_rather_than_a_zero_one() {
        let s = Summary::of(&[7.0]).unwrap();
        assert_eq!((s.n, s.mean, s.sd), (1, 7.0, None));
        assert_eq!(format!("{s:.1}"), "7.0 (n=1)");
    }

    #[test]
    fn the_spread_is_the_sample_deviation() {
        let s = Summary::of(&[10.0, 12.0, 14.0]).unwrap();
        assert_eq!(s.mean, 12.0);
        assert_eq!(s.median, 12.0);
        assert!((s.sd.unwrap() - 2.0).abs() < 1e-12);
    }

    /// A skewed set is where a median and a mean part company, which is the
    /// case worth keeping both for.
    #[test]
    fn a_single_outlier_moves_the_mean_and_not_the_median() {
        let s = Summary::of(&[10.0, 10.0, 10.0, 10.0, 100.0]).unwrap();
        assert_eq!(s.median, 10.0);
        assert_eq!(s.mean, 28.0);
        assert!(s.rsd().unwrap() > 1.0);
    }

    #[test]
    fn overlapping_measurements_are_not_ordered() {
        let fast = Summary::of(&[10.0, 11.0, 12.0]).unwrap();
        let slow = Summary::of(&[12.0, 13.0, 14.0]).unwrap();
        // The means differ, but the intervals touch, so no crossover is claimed.
        assert!(fast.mean < slow.mean);
        assert!(!fast.below(&slow));

        let clearly_slower = Summary::of(&[40.0, 41.0, 42.0]).unwrap();
        assert!(fast.below(&clearly_slower));
    }

    #[test]
    fn exact_quantities_say_so() {
        assert_eq!(Exact(287).json(), "{\"exact\": 287}");
        assert_eq!(format!("{}", Exact(287)), "287 (exact)");
    }
}
