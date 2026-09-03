//! Three ways of telling the market something, compared by the study.
//!
//! - **none** — only the counterparties see the firm price.
//! - **threshold** — an exact statement: at least K independent makers can fill
//!   at least V lots inside a band around the reference mid. No noise, but the
//!   statement is suppressed when it is false.
//! - **dp** — entity-clipped statistics released every window with discrete
//!   Laplace noise and a per-entity continual-observation budget.
//!
//! The DP mechanism uses entity-level adjacency: two datasets differ by removing
//! every request, quote, update and trade made by one legal entity. That is the
//! unit the design protects, and it is why the sensitivity is a per-entity clip
//! rather than a per-record bound --- which turns out to decide what the
//! mechanism can and cannot publish.

use std::collections::{BTreeMap, BTreeSet};

use crate::deterministic_random::DeterministicRng;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PrivacyBudgetExceeded {
    pub spent: f64,
    pub wanted: f64,
    pub limit: f64,
}

impl std::fmt::Display for PrivacyBudgetExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "budget exhausted: spent={:.3} want={:.3} cap={}",
            self.spent, self.wanted, self.limit
        )
    }
}

impl std::error::Error for PrivacyBudgetExceeded {}

/// Continual-observation budget, tracked per protected entity.
#[derive(Clone, Debug)]
pub struct EntityAccountant {
    pub epsilon_total: f64,
    pub spent: f64,
    pub releases: u64,
    /// Zero selects pure-DP basic composition. A positive value selects the
    /// published advanced-composition bound.
    pub delta: f64,
}

impl EntityAccountant {
    pub fn new(epsilon_total: f64) -> Self {
        EntityAccountant {
            epsilon_total,
            spent: 0.0,
            releases: 0,
            delta: 0.0,
        }
    }
    pub fn with_delta(epsilon_total: f64, delta: f64) -> Self {
        Self {
            delta,
            ..Self::new(epsilon_total)
        }
    }
    fn cost(&self, releases: u64, epsilon: f64) -> f64 {
        advanced_composition(epsilon, releases, self.delta)
    }
    pub fn can_spend(&self, epsilon: f64) -> bool {
        self.cost(self.releases + 1, epsilon) <= self.epsilon_total + 1e-12
    }
    pub fn spend(&mut self, epsilon: f64) {
        self.try_spend(epsilon)
            .unwrap_or_else(|error| panic!("{error}"));
    }
    pub fn try_spend(&mut self, epsilon: f64) -> Result<(), PrivacyBudgetExceeded> {
        if !self.can_spend(epsilon) {
            return Err(PrivacyBudgetExceeded {
                spent: self.spent,
                wanted: epsilon,
                limit: self.epsilon_total,
            });
        }
        self.releases += 1;
        self.spent = self.cost(self.releases, epsilon);
        Ok(())
    }
}

/// Dwork--Rothblum--Vadhan advanced composition; delta zero is basic composition.
pub fn advanced_composition(epsilon_0: f64, k: u64, delta: f64) -> f64 {
    if k == 0 {
        return 0.0;
    }
    if delta <= 0.0 {
        return k as f64 * epsilon_0;
    }
    (2.0 * k as f64 * (1.0 / delta).ln()).sqrt() * epsilon_0
        + k as f64 * epsilon_0 * epsilon_0.exp_m1()
}

pub const RATE_DENOMINATOR_LIMIT: u64 = 10_000_000;

/// Exact positive rational represented by an `f64`, reduced by powers of two.
fn float_ratio(value: f64) -> (u128, u128) {
    assert!(value.is_finite() && value >= 0.0);
    if value == 0.0 {
        return (0, 1);
    }
    let bits = value.to_bits();
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mut numerator, exponent) = if exponent_bits == 0 {
        (fraction as u128, -1022 - 52)
    } else {
        (((1u64 << 52) | fraction) as u128, exponent_bits - 1023 - 52)
    };
    if exponent >= 0 {
        return (numerator << exponent, 1);
    }
    let mut denominator_exponent = (-exponent) as u32;
    let removable = numerator.trailing_zeros().min(denominator_exponent);
    numerator >>= removable;
    denominator_exponent -= removable;
    assert!(
        denominator_exponent < 128,
        "noise rate is too small to represent"
    );
    (numerator, 1u128 << denominator_exponent)
}

/// Best bounded-denominator rational approximation using continued fractions.
fn limit_denominator(value: f64, max_denominator: u64) -> (u64, u64) {
    let (mut numerator, mut denominator) = float_ratio(value);
    if denominator <= max_denominator as u128 {
        return (numerator as u64, denominator as u64);
    }

    let (mut p0, mut q0, mut p1, mut q1) = (0u128, 1u128, 1u128, 0u128);
    loop {
        let a = numerator / denominator;
        let q2 = q0 + a * q1;
        if q2 > max_denominator as u128 {
            break;
        }
        (p0, q0, p1, q1) = (p1, q1, p0 + a * p1, q2);
        (numerator, denominator) = (denominator, numerator - a * denominator);
    }
    let k = (max_denominator as u128 - q0) / q1;
    let bound1 = (p0 + k * p1, q0 + k * q1);
    let bound2 = (p1, q1);
    let distance1 = (value - bound1.0 as f64 / bound1.1 as f64).abs();
    let distance2 = (value - bound2.0 as f64 / bound2.1 as f64).abs();
    let chosen = if distance2 <= distance1 {
        bound2
    } else {
        bound1
    };
    (chosen.0 as u64, chosen.1 as u64)
}

/// A fair-coin construction for a Bernoulli with probability `exp(-n/d)`.
fn bernoulli_exp_minus(numerator: u64, denominator: u64, rng: &mut DeterministicRng) -> bool {
    assert!(denominator > 0);
    if numerator > denominator {
        let whole = numerator / denominator;
        let rest = numerator % denominator;
        for _ in 0..whole {
            if !bernoulli_exp_minus(1, 1, rng) {
                return false;
            }
        }
        return bernoulli_exp_minus(rest, denominator, rng);
    }
    let mut k = 1u64;
    loop {
        let stop = denominator
            .checked_mul(k)
            .and_then(|v| i64::try_from(v).ok())
            .expect("exact geometric denominator overflow");
        if rng.randrange(0, stop) as u64 >= numerator {
            break;
        }
        k += 1;
    }
    k % 2 == 1
}

fn geometric_exact(numerator: u64, denominator: u64, rng: &mut DeterministicRng) -> i64 {
    let mut count = 0i64;
    while bernoulli_exp_minus(numerator, denominator, rng) {
        count += 1;
    }
    count
}

/// Two-sided geometric noise sampled with integer comparisons only.
///
/// privacy proof, rather than the distinguishable floating-point inverse-CDF
/// approximation.
pub fn discrete_laplace(epsilon: f64, sensitivity: f64, rng: &mut DeterministicRng) -> i64 {
    assert!(
        sensitivity > 0.0 && epsilon > 0.0,
        "sensitivity and epsilon must be positive"
    );
    let rate = epsilon / sensitivity;
    if rate >= 64.0 {
        return 0;
    }
    let (numerator, denominator) = limit_denominator(rate, RATE_DENOMINATOR_LIMIT);
    assert!(numerator > 0, "the noise rate rounded to zero");
    if numerator >= 64 * denominator {
        return 0;
    }
    geometric_exact(numerator, denominator, rng) - geometric_exact(numerator, denominator, rng)
}

/// The former floating-point inverse-CDF sampler, kept only so old experiment
/// results can be reproduced explicitly. New privacy releases use
/// [`discrete_laplace`].
pub fn discrete_laplace_approximate(
    epsilon: f64,
    sensitivity: f64,
    rng: &mut DeterministicRng,
) -> i64 {
    assert!(
        sensitivity > 0.0 && epsilon > 0.0,
        "sensitivity and epsilon must be positive"
    );
    let alpha = (-epsilon / sensitivity).exp();
    if alpha <= 0.0 {
        return 0;
    }
    let geometric =
        |rng: &mut DeterministicRng| ((-rng.random()).ln_1p() / alpha.ln()).floor() as i64;
    geometric(rng) - geometric(rng)
}

/// Recover `|S|` from a noisy `|S + N|`.
///
/// Symmetric noise biases an absolute value upward: for scale `b`,
/// `E|S+N| = |S| + b·exp(-|S|/b)`, so perfectly balanced flow publishes as `b`
/// of imbalance and makers widen against informed flow that is not there. Soft
/// thresholding at the published scale corrects it deterministically, so a
/// reader recomputes it from public figures.
pub fn debias_absolute(observed: f64, scale: f64) -> f64 {
    if scale <= 0.0 {
        return observed.abs();
    }
    (observed.abs() - scale).max(0.0)
}

/// Ground truth for one window, before any protection.
#[derive(Clone, Debug, Default)]
pub struct WindowObservation {
    pub window: usize,
    pub start_step: usize,
    pub end_step: usize,
    pub requests_by_entity: BTreeMap<usize, i64>,
    pub volume_by_entity: BTreeMap<usize, i64>,
    pub signed_volume_by_entity: BTreeMap<usize, i64>,
    pub fills_by_entity: BTreeMap<usize, i64>,
    pub fills: i64,
    pub requests: i64,
    pub no_quote: i64,
    pub liquidity_lots_in_band: i64,
    pub makers_in_band: i64,
    pub fills_by_bucket: [i64; 3],
    pub requests_by_bucket: [i64; 3],
}

#[derive(Clone, Debug, Default)]
pub struct ReleaseFields {
    pub noisy_requests: i64,
    pub noisy_volume: i64,
    pub noisy_signed_volume: i64,
    pub noisy_fills: i64,
    pub fill_rate: Option<f64>,
    /// Kept for error measurement only; never seen by a maker.
    pub exact_requests: i64,
    pub exact_volume: i64,
    pub exact_signed_volume: i64,
    pub exact_fills: i64,
    pub request_cap: i64,
    pub volume_cap: i64,
    pub noise_scale_requests: f64,
    pub noise_scale_signed: f64,
    pub debiased: bool,
    pub min_makers: i64,
    pub min_lots: i64,
    /// Exact informed fraction used only by the disclosure-ceiling experiment.
    pub phi: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct Release {
    pub window: usize,
    pub mode: &'static str,
    pub published: bool,
    pub fields: ReleaseFields,
    pub epsilon_spent: f64,
    pub suppressed_reason: &'static str,
}

/// An estimate of the informed fraction and its variance. Infinite variance
/// means the channel said nothing usable, which is a result rather than a bug.
pub type PublicSignal = (Option<f64>, f64);

pub enum Disclosure {
    None,
    Threshold {
        min_makers: i64,
        min_lots: i64,
    },
    Dp(Box<DpDisclosure>),
    Oracle {
        phi_by_window: BTreeMap<usize, f64>,
        reaches: Option<BTreeSet<usize>>,
    },
}

pub struct DpDisclosure {
    pub epsilon_per_window: f64,
    pub request_cap: i64,
    pub volume_cap: i64,
    pub accountants: BTreeMap<usize, EntityAccountant>,
    pub n_fields: f64,
    pub debias: bool,
    /// Three fields take one entity's cap, which is what the audited adjacency
    /// calls for. The signed field alone took twice that --- the replace-one
    /// figure --- which doubled its noise for no gain in privacy.
    pub signed_sensitivity_factor: f64,
    /// Optional subscriber set.  `None` is a venue-wide release; `Some` lets
    /// the simulator separate the information effect of a disclosure from the
    /// competition effect of every maker receiving it.
    pub reaches: Option<BTreeSet<usize>>,
}

/// A satisfied depth statement says the market is not stressed, which shifts the
/// estimate modestly below the population base. It is one bit, so the residual
/// variance stays wide; setting it to zero would be wrong, because the statement
/// is about depth and not about who is trading.
const CALM_ESTIMATE: f64 = 0.24;
const CALM_VARIANCE: f64 = 0.16;

impl Disclosure {
    pub fn name(&self) -> &'static str {
        match self {
            Disclosure::None => "A_none",
            Disclosure::Threshold { .. } => "B_threshold",
            Disclosure::Dp(_) => "C_dp",
            Disclosure::Oracle { .. } => "Z_oracle",
        }
    }

    pub fn release(&mut self, obs: &WindowObservation, rng: &mut DeterministicRng) -> Release {
        match self {
            Disclosure::None => Release {
                window: obs.window,
                mode: "none",
                published: false,
                fields: ReleaseFields::default(),
                epsilon_spent: 0.0,
                suppressed_reason: "arm A publishes nothing",
            },
            Disclosure::Threshold {
                min_makers,
                min_lots,
            } => {
                let holds =
                    obs.makers_in_band >= *min_makers && obs.liquidity_lots_in_band >= *min_lots;
                if !holds {
                    return Release {
                        window: obs.window,
                        mode: "B_threshold",
                        published: false,
                        fields: ReleaseFields::default(),
                        epsilon_spent: 0.0,
                        suppressed_reason: "threshold statement not satisfied",
                    };
                }
                Release {
                    window: obs.window,
                    mode: "B_threshold",
                    published: true,
                    fields: ReleaseFields {
                        min_makers: *min_makers,
                        min_lots: *min_lots,
                        ..ReleaseFields::default()
                    },
                    epsilon_spent: 0.0,
                    suppressed_reason: "",
                }
            }
            Disclosure::Dp(dp) => dp.release(obs, rng),
            Disclosure::Oracle { phi_by_window, .. } => Release {
                window: obs.window,
                mode: "Z_oracle",
                published: true,
                fields: ReleaseFields {
                    phi: Some(*phi_by_window.get(&obs.window).unwrap_or(&0.45)),
                    ..ReleaseFields::default()
                },
                epsilon_spent: 0.0,
                suppressed_reason: "",
            },
        }
    }

    pub fn public_signal(&self, release: &Release) -> PublicSignal {
        match self {
            Disclosure::None => (None, f64::INFINITY),
            Disclosure::Threshold { .. } => {
                if release.published {
                    (Some(CALM_ESTIMATE), CALM_VARIANCE)
                } else {
                    (None, f64::INFINITY)
                }
            }
            Disclosure::Dp(dp) => dp.public_signal(release),
            Disclosure::Oracle { .. } => {
                if release.published {
                    (release.fields.phi, 1e-4)
                } else {
                    (None, f64::INFINITY)
                }
            }
        }
    }

    /// Whether this disclosure reaches a particular maker.
    pub fn reaches(&self, mm_id: usize) -> bool {
        match self {
            Disclosure::Dp(dp) => dp
                .reaches
                .as_ref()
                .is_none_or(|subscribers| subscribers.contains(&mm_id)),
            Disclosure::Oracle { reaches, .. } => reaches
                .as_ref()
                .is_none_or(|subscribers| subscribers.contains(&mm_id)),
            _ => true,
        }
    }

    pub fn epsilon_spent_max(&self) -> f64 {
        match self {
            Disclosure::Dp(dp) => dp.accountants.values().map(|a| a.spent).fold(0.0, f64::max),
            Disclosure::Oracle { .. } => 0.0,
            _ => 0.0,
        }
    }
}

impl DpDisclosure {
    pub fn new(
        epsilon_per_window: f64,
        request_cap: i64,
        volume_cap: i64,
        entities: usize,
        epsilon_total: f64,
        debias: bool,
    ) -> Self {
        DpDisclosure {
            epsilon_per_window,
            request_cap,
            volume_cap,
            accountants: (0..entities)
                .map(|e| (e, EntityAccountant::new(epsilon_total)))
                .collect(),
            n_fields: 4.0,
            debias,
            signed_sensitivity_factor: 1.0,
            reaches: None,
        }
    }

    pub fn release(&mut self, obs: &WindowObservation, rng: &mut DeterministicRng) -> Release {
        // Whether a scheduled window is published must not reveal which
        // entities contributed to it.  Budget-checking only active entities
        // made the published/withheld bit distinguish presence with
        // probability one.  The schedule therefore checks and charges every
        // enrolled entity, including entities that sat this window out.
        if self
            .accountants
            .values()
            .any(|a| !a.can_spend(self.epsilon_per_window))
        {
            return Release {
                window: obs.window,
                mode: "C_dp",
                published: false,
                fields: ReleaseFields::default(),
                epsilon_spent: 0.0,
                suppressed_reason: "entity privacy budget exhausted",
            };
        }
        for accountant in self.accountants.values_mut() {
            accountant.spend(self.epsilon_per_window);
        }

        let eps = self.epsilon_per_window / self.n_fields;
        let clipped_requests: i64 = obs
            .requests_by_entity
            .values()
            .map(|c| (*c).min(self.request_cap))
            .sum();
        let clipped_volume: i64 = obs
            .volume_by_entity
            .values()
            .map(|v| (*v).min(self.volume_cap))
            .sum();
        let clipped_signed: i64 = obs
            .signed_volume_by_entity
            .values()
            .map(|v| (*v).clamp(-self.volume_cap, self.volume_cap))
            .sum();
        // Entity adjacency applies to fills too.  Clipping a bare fill total
        // against the request sum lets one entity move this field by many
        // caps; clip each entity's contribution before summing instead.
        let clipped_fills: i64 = obs
            .fills_by_entity
            .values()
            .map(|c| (*c).min(self.request_cap))
            .sum();

        let request_cap = self.request_cap as f64;
        let volume_cap = self.volume_cap as f64;
        let signed_sensitivity = self.signed_sensitivity_factor * volume_cap;

        let noisy_requests = (clipped_requests + discrete_laplace(eps, request_cap, rng)).max(0);
        let noisy_volume = (clipped_volume + discrete_laplace(eps, volume_cap, rng)).max(0);
        let noisy_signed = clipped_signed + discrete_laplace(eps, signed_sensitivity, rng);
        let noisy_fills = (clipped_fills + discrete_laplace(eps, request_cap, rng)).max(0);

        Release {
            window: obs.window,
            mode: "C_dp",
            published: true,
            fields: ReleaseFields {
                noisy_requests,
                noisy_volume,
                noisy_signed_volume: noisy_signed,
                noisy_fills,
                fill_rate: if noisy_requests > 0 {
                    Some(noisy_fills as f64 / noisy_requests as f64)
                } else {
                    None
                },
                exact_requests: clipped_requests,
                exact_volume: clipped_volume,
                exact_signed_volume: clipped_signed,
                exact_fills: clipped_fills,
                request_cap: self.request_cap,
                volume_cap: self.volume_cap,
                noise_scale_requests: request_cap / eps,
                noise_scale_signed: signed_sensitivity / eps,
                debiased: self.debias,
                min_makers: 0,
                min_lots: 0,
                phi: None,
            },
            epsilon_spent: self.epsilon_per_window,
            suppressed_reason: "",
        }
    }

    /// Signed order-flow imbalance is the public proxy for informed flow.
    pub fn public_signal(&self, release: &Release) -> PublicSignal {
        if !release.published {
            return (None, f64::INFINITY);
        }
        let volume = release.fields.noisy_volume;
        if volume <= 0 {
            return (None, f64::INFINITY);
        }
        let signed = release.fields.noisy_signed_volume as f64;
        let magnitude = if release.fields.debiased {
            debias_absolute(signed, release.fields.noise_scale_signed)
        } else {
            signed.abs()
        };
        let imbalance = magnitude / (volume.max(1) as f64);
        let estimate = imbalance.clamp(0.0, 0.95);
        // sampling variance plus the DP noise contribution
        let noise_sd = release.fields.noise_scale_signed * 2.0f64.sqrt();
        let var = 0.02 + (noise_sd / (volume.max(1) as f64)).powi(2);
        (Some(estimate), var)
    }
}
