//! Auditing the privacy claim in the form of its definition.
//!
//! An AUC-style attack cannot confirm an epsilon claim, because individual and
//! aggregate activity are correlated in the population even under perfect
//! privacy. What can confirm it is the two-world game the definition is written
//! in: run the mechanism many times on a world containing one entity and on the
//! world without it, and ask how well any threshold separates the two output
//! distributions.
//!
//! Two details make the bound honest. The threshold is chosen after seeing the
//! samples, so a single 95% interval per threshold would report a violation on a
//! correct mechanism about one time in twenty --- Bonferroni over the candidate
//! set fixes that. And the audited statistic is one of several released per
//! window, so the claim binding it is the per-field share of the budget rather
//! than the whole thing.

use crate::disclosure::{DpDisclosure, WindowObservation};
use crate::pyrandom::PyRandom;
pub use qomm_measure::beta::{beta_ppf, betainc_public};
use qomm_measure::beta::ln;

pub fn clopper_pearson(k: usize, n: usize, alpha: f64) -> (f64, f64) {
    let lower = if k == 0 {
        0.0
    } else {
        beta_ppf(alpha / 2.0, k as f64, (n - k + 1) as f64)
    };
    let upper = if k == n {
        1.0
    } else {
        beta_ppf(1.0 - alpha / 2.0, (k + 1) as f64, (n - k) as f64)
    };
    (lower, upper)
}

#[derive(Clone, Debug)]
pub struct AuditResult {
    pub window: usize,
    pub entity: usize,
    pub trials: usize,
    pub declared_epsilon: f64,
    pub field_epsilon: f64,
    pub empirical_epsilon: f64,
    pub best_threshold: f64,
    pub within_claim: bool,
    pub entity_requests: i64,
    pub entity_volume: i64,
}

/// Which released field the audit binds.
///
/// Only the request count used to be testable, which left the other three
/// carrying an epsilon claim nothing had ever bound. The signed volume matters
/// most, because it is the one whose noise scale is in question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Requests,
    Volume,
    SignedVolume,
    Fills,
}

impl Field {
    fn read(&self, fields: &crate::disclosure::ReleaseFields) -> f64 {
        match self {
            Field::Requests => fields.noisy_requests as f64,
            Field::Volume => fields.noisy_volume as f64,
            Field::SignedVolume => fields.noisy_signed_volume as f64,
            Field::Fills => fields.noisy_fills as f64,
        }
    }
}

pub fn drop_entity(obs: &WindowObservation, entity: usize) -> WindowObservation {
    let without = |m: &std::collections::BTreeMap<usize, i64>| {
        m.iter()
            .filter(|(k, _)| **k != entity)
            .map(|(k, v)| (*k, *v))
            .collect()
    };
    let requests_by_entity: std::collections::BTreeMap<usize, i64> =
        without(&obs.requests_by_entity);
    let fills_by_entity: std::collections::BTreeMap<usize, i64> = without(&obs.fills_by_entity);
    WindowObservation {
        requests: requests_by_entity.values().sum(),
        fills: fills_by_entity.values().sum(),
        requests_by_entity,
        volume_by_entity: without(&obs.volume_by_entity),
        signed_volume_by_entity: without(&obs.signed_volume_by_entity),
        fills_by_entity,
        ..obs.clone()
    }
}

pub struct AuditSettings {
    pub epsilon_per_window: f64,
    pub request_cap: i64,
    pub volume_cap: i64,
    pub trials: usize,
    pub seed: u64,
    pub n_entities: usize,
    pub n_fields: f64,
    pub field: Field,
    pub signed_sensitivity_factor: f64,
}

impl Default for AuditSettings {
    fn default() -> Self {
        AuditSettings {
            epsilon_per_window: 1.0,
            request_cap: 3,
            volume_cap: 300,
            trials: 4_000,
            seed: 1,
            n_entities: 64,
            n_fields: 4.0,
            field: Field::Requests,
            signed_sensitivity_factor: 1.0,
        }
    }
}

/// Distinguish "entity present" from "entity absent" using one released field.
pub fn audit_window(obs: &WindowObservation, entity: usize, s: &AuditSettings) -> AuditResult {
    let mut rng = PyRandom::new(s.seed);
    let world_out = drop_entity(obs, entity);

    let sample = |world: &WindowObservation, rng: &mut PyRandom| -> Vec<f64> {
        (0..s.trials)
            .map(|_| {
                let mut mech = DpDisclosure::new(
                    s.epsilon_per_window,
                    s.request_cap,
                    s.volume_cap,
                    s.n_entities,
                    1e9,
                    true,
                );
                mech.signed_sensitivity_factor = s.signed_sensitivity_factor;
                let release = crate::disclosure::Disclosure::Dp(Box::new(mech)).release(world, rng);
                s.field.read(&release.fields)
            })
            .collect()
    };
    let samples_in = sample(obs, &mut rng);
    let samples_out = sample(&world_out, &mut rng);

    let mut candidates: Vec<i64> = samples_in
        .iter()
        .chain(&samples_out)
        .map(|v| crate::market::py_round(*v))
        .collect();
    candidates.sort_unstable();
    candidates.dedup();

    // Bonferroni over the candidate set, because the threshold is chosen after
    // seeing the samples.
    let alpha = 0.05 / candidates.len().max(1) as f64;
    let (mut best_eps, mut best_threshold) = (0.0f64, 0.0f64);
    for threshold in candidates {
        let t = threshold as f64;
        let k_in = samples_in.iter().filter(|v| **v >= t).count();
        let k_out = samples_out.iter().filter(|v| **v >= t).count();
        let (tpr_lo, _) = clopper_pearson(k_in, s.trials, alpha);
        let (_, fpr_hi) = clopper_pearson(k_out, s.trials, alpha);
        for (num, den) in [(tpr_lo, fpr_hi), (1.0 - fpr_hi, 1.0 - tpr_lo)] {
            if den > 0.0 && num > 0.0 {
                let candidate = ln(num / den);
                if candidate > best_eps {
                    best_eps = candidate;
                    best_threshold = t;
                }
            }
        }
    }

    let field_epsilon = s.epsilon_per_window / s.n_fields;
    AuditResult {
        window: obs.window,
        entity,
        trials: s.trials,
        declared_epsilon: s.epsilon_per_window,
        field_epsilon,
        empirical_epsilon: best_eps,
        best_threshold,
        within_claim: best_eps <= field_epsilon + 1e-9,
        entity_requests: obs.requests_by_entity.get(&entity).copied().unwrap_or(0),
        entity_volume: obs.volume_by_entity.get(&entity).copied().unwrap_or(0),
    }
}
