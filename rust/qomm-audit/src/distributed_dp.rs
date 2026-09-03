//! Distributed discrete-Laplace publication inside the MPC.

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"QOMM:DISTRIBUTED-DP:v1";
pub const U64_SPACE: u128 = 1_u128 << 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpMechanism {
    pub epsilon_micros: u64,
    pub sensitivity: u64,
    pub support: u16,
    pub version: String,
}

impl DpMechanism {
    pub fn new(epsilon_micros: u64, sensitivity: u64, support: u16) -> Result<Self, String> {
        if epsilon_micros == 0 || sensitivity == 0 {
            return Err("epsilon and sensitivity must be positive".into());
        }
        if !(1..=4096).contains(&support) {
            return Err("support must lie in 1..4096".into());
        }
        Ok(Self {
            epsilon_micros,
            sensitivity,
            support,
            version: "distributed-discrete-laplace-v1".into(),
        })
    }

    /// A bound on the total-variation distance between the cells this mechanism
    /// actually releases and the exact truncated two-sided geometric.
    ///
    /// It is *not* `(2s+1)/2^64`, which is what an earlier version returned.
    /// That is the cost of flooring the endpoints alone, and it is not the
    /// binding term: `thresholds` accumulates the cumulative distribution in
    /// `f64`, whose resolution near one is `2^-53` rather than `2^-64`, so the
    /// endpoints inherit an error four thousand times coarser than the grid
    /// they are floored onto. Measured against exact arithmetic, the real
    /// distance runs 2.4e-16 to 6.7e-16 over supports 8 to 32 at epsilon 1,
    /// against an old bound of 9.2e-19 to 3.5e-18 --- so the old value was not
    /// conservative, it was wrong by about 250x.
    ///
    /// Derivation of what is returned. Accumulating `2s+1` terms whose partial
    /// sums never exceed one leaves an absolute error in `cumulative` of at
    /// most `(2s+1) * 2^-53`. Each endpoint is that, floored onto a `2^-64`
    /// grid, so it carries at most `(2s+1) * 2^-53 + 2^-64`. A cell is a
    /// difference of two endpoints and `2s+1` cells are summed and halved, so
    /// the distance is at most `(2s+1)^2 * 2^-53 + (2s+1) * 2^-64`, and
    /// `((2s+1)^2 + 1) / 2^53` covers both terms for every support this type
    /// admits. `rounding_delta_is_a_bound_and_the_old_one_was_not` checks it
    /// against the distance computed in exact rationals.
    ///
    /// None of this is the `delta` a certificate should carry. That is
    /// `privacy_delta`, which the truncation dominates --- by twelve orders of
    /// magnitude at support 8, eight at 16, and only tenfold by 32, since one
    /// decays as `alpha^support` while this grows with the cell count.
    pub fn rounding_delta(&self) -> (u64, u128) {
        let cells = 2 * u64::from(self.support) + 1;
        (cells * cells + 1, 1_u128 << 53)
    }

    /// The `delta` this mechanism needs to be `(epsilon, delta)`-differentially
    /// private, because it truncates. This is what a certificate has to carry.
    ///
    /// The support is finite and the tails are folded onto the endpoints, so
    /// two adjacent inputs produce releases whose supports are offset by the
    /// sensitivity. At the edges one assigns mass where the other assigns none,
    /// and no `epsilon` bounds that ratio.
    ///
    /// It is computed here rather than given in closed form, and the reason is
    /// that the closed forms are wrong. Naming the folded tail understates it by
    /// `e^epsilon`, because the endpoint cell carries the folded tail *and* the
    /// point at the support. Naming the endpoint cell understates it whenever
    /// the sensitivity exceeds one, because then the supports are offset by more
    /// than one cell and several cells escape --- at `epsilon = 0.5`,
    /// sensitivity 3 and support 24 the endpoint cell is `0.0099` against a true
    /// `delta` about twice that. And both ignore that the folded endpoints carry
    /// far more mass than the geometric ratio allows, so cells near an edge can
    /// exceed `e^epsilon` without being outside the support at all.
    ///
    /// So this returns the hockey-stick divergence at `e^epsilon`, maximised
    /// over every shift the sensitivity permits, over the cells the mechanism
    /// actually releases rather than over the ideal law it approximates.
    pub fn privacy_delta(&self) -> Result<f64, String> {
        let cells = self.released_cells()?;
        let epsilon = self.epsilon_micros as f64 / 1_000_000.0;
        let ratio = epsilon.exp();
        let width = cells.len() as i64;
        let sensitivity = self.sensitivity.min(u64::MAX / 2) as i64;
        let mut worst = 0.0_f64;
        for shift in 1..=sensitivity {
            for direction in [shift, -shift] {
                let mut divergence = 0.0;
                for (index, probability) in cells.iter().enumerate() {
                    let other = index as i64 - direction;
                    let neighbour = if (0..width).contains(&other) {
                        cells[other as usize]
                    } else {
                        0.0
                    };
                    // `ratio` overflows to infinity once epsilon passes
                    // ln(f64::MAX), and `infinity * 0.0` is NaN, which
                    // `f64::max` silently resolves to the other operand. That
                    // turned every escaping cell into a zero contribution and
                    // returned delta 0 where the true delta was 1. The neighbour
                    // being absent is the case that matters most, so it is
                    // written out rather than left to arithmetic.
                    let scaled = if neighbour == 0.0 {
                        0.0
                    } else {
                        ratio * neighbour
                    };
                    divergence += (probability - scaled).max(0.0);
                }
                worst = worst.max(divergence);
            }
        }
        Ok(worst)
    }

    /// `privacy_delta` as the rational a `PublicationStatement` carries.
    ///
    /// A statement used to bind `rounding_delta`, which is the distance between
    /// the released cells and the law they approximate --- not a privacy
    /// parameter at all, and ten orders of magnitude smaller than one at
    /// support 8. A certificate that understates its own `delta` by ten orders
    /// is worse than one that carries none.
    pub fn certificate_delta(&self) -> Result<(u64, u128), String> {
        let delta = self.privacy_delta()?;
        let denominator = 1_u128 << 53;
        let numerator = (delta * denominator as f64).ceil();
        if !numerator.is_finite() || numerator < 0.0 {
            return Err(format!("delta is not a probability: {delta}"));
        }
        if numerator >= denominator as f64 {
            // A delta at or near one is not a rounding problem. It means the
            // sensitivity has shifted the support clear of itself, or nearly,
            // so adjacent inputs are all but distinguishable and the mechanism
            // provides no guarantee to certify. Refusing is the right answer:
            // a statement cannot express it, and should not pretend to.
            return Err(format!(
                "delta {delta} leaves no guarantee to certify: support {} is too \
                 narrow for sensitivity {} at this epsilon",
                self.support, self.sensitivity
            ));
        }
        Ok((numerator as u64, denominator))
    }

    /// The cell probabilities as released: differences of the quantised
    /// endpoints, not the `f64` law they were derived from.
    pub fn released_cells(&self) -> Result<Vec<f64>, String> {
        let endpoints = self.thresholds()?;
        let mut previous = 0_u128;
        let mut cells = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            cells.push((endpoint - previous) as f64 / U64_SPACE as f64);
            previous = endpoint;
        }
        Ok(cells)
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(self.version.as_bytes())
            .chain_update(self.epsilon_micros.to_be_bytes())
            .chain_update(self.sensitivity.to_be_bytes())
            .chain_update(u32::from(self.support).to_be_bytes())
            .finalize()
            .into()
    }

    /// Quantised CDF endpoints over `[0, 2^64)`. The final endpoint is kept as
    /// `u128` because it is exactly one past `u64::MAX`.
    pub fn thresholds(&self) -> Result<Vec<u128>, String> {
        let epsilon = self.epsilon_micros as f64 / 1_000_000.0;
        let alpha = (-epsilon / self.sensitivity as f64).exp();
        let normalizer = (1.0 - alpha) / (1.0 + alpha);
        let support = i32::from(self.support);
        let tail = normalizer * alpha.powi(support) / (1.0 - alpha);
        let mut probabilities = Vec::with_capacity(usize::from(self.support) * 2 + 1);
        probabilities.push(tail);
        for value in (-support + 1)..support {
            probabilities.push(normalizer * alpha.powi(value.abs()));
        }
        probabilities.push(tail);
        let mut cumulative = 0.0_f64;
        let mut endpoints = Vec::with_capacity(probabilities.len());
        for (index, probability) in probabilities.iter().enumerate() {
            cumulative += probability;
            let endpoint = if index + 1 == probabilities.len() {
                U64_SPACE
            } else {
                (cumulative * U64_SPACE as f64).floor() as u128
            };
            if endpoints
                .last()
                .is_some_and(|previous| endpoint <= *previous)
            {
                return Err(
                    "64-bit CDF has a zero-probability cell; lower support or epsilon".into(),
                );
            }
            endpoints.push(endpoint);
        }
        Ok(endpoints)
    }

    pub fn sample_u64(&self, uniform: u64) -> Result<i32, String> {
        let endpoints = self.thresholds()?;
        let index = endpoints.partition_point(|endpoint| *endpoint <= u128::from(uniform));
        Ok(-i32::from(self.support) + index as i32)
    }

    pub fn mp_spdz_source(
        &self,
        n_parties: usize,
        budget_total_micros: u64,
        budget_spent_micros: u64,
        label: &str,
    ) -> Result<String, String> {
        if n_parties < 3 {
            return Err("distributed publication requires at least three nodes".into());
        }
        let after = budget_spent_micros
            .checked_add(self.epsilon_micros)
            .ok_or_else(|| "the requested release exceeds its privacy budget".to_string())?;
        if after > budget_total_micros {
            return Err("the requested release exceeds its privacy budget".into());
        }
        if label.is_empty()
            || !label
                .chars()
                .next()
                .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
            || !label
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
        {
            return Err("output label must be an ASCII identifier".into());
        }
        let thresholds = self.thresholds()?;
        let comparisons = thresholds[..thresholds.len() - 1]
            .iter()
            .map(|threshold| format!("u.__ge__({threshold})"))
            .collect::<Vec<_>>()
            .join(" + ");
        Ok(format!(
            "# generated by qomm_audit.distributed_dp; do not edit\n\
             from Compiler.types import sint\n\
             N_PARTIES = {n_parties}\n\
             EPSILON_MICROS = {}\n\
             BUDGET_BEFORE_MICROS = {budget_spent_micros}\n\
             BUDGET_AFTER_MICROS = {after}\n\
             exact = sum(sint.get_input_from(p) for p in range(N_PARTIES))\n\
             random_bits = [sint.get_random_bit() for _ in range(64)]\n\
             u = sum(random_bits[j] * (1 << j) for j in range(64))\n\
             noise = -{} + ({comparisons})\n\
             {label} = exact + noise\n\
             print_ln('%s', {label}.reveal())\n",
            self.epsilon_micros, self.support
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetState {
    pub total_micros: u64,
    pub spent_micros: u64,
}

impl BudgetState {
    pub fn spend(self, mechanism: &DpMechanism) -> Result<Self, String> {
        let spent = self
            .spent_micros
            .checked_add(mechanism.epsilon_micros)
            .ok_or_else(|| "privacy budget exhausted".to_string())?;
        if spent > self.total_micros {
            return Err("privacy budget exhausted".into());
        }
        Ok(Self {
            total_micros: self.total_micros,
            spent_micros: spent,
        })
    }
}
