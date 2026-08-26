//! Questions an asker pays for, instead of statistics somebody chose to publish.
//!
//! The scheduled disclosure publishes four sums every window.  That shape has
//! three structural defects:
//!
//! 1. A sum moves by an entity's whole cap, while a distinct-entity count moves
//!    by exactly one.  Range-query noise therefore has sensitivity one at every
//!    width.
//! 2. Thresholds and centred bands need an operator to choose market
//!    parameters.  Here the asker supplies its own public price or block range.
//! 3. A scheduled release charges every enrolled entity even when nobody asked
//!    for it.  Here only the asker spends budget, so refusals depend on the
//!    asker's own history and never on makers' private data.
//!
//! Pricing controls how much of the finite epsilon ceiling an asker can afford;
//! it does not replace that ceiling.

use std::collections::BTreeSet;

use crate::disclosure::{discrete_laplace, EntityAccountant, WindowObservation};
use crate::pyrandom::PyRandom;

/// One entity is either inside a range or it is not.
pub const SENSITIVITY: i64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeQuery {
    pub low: i64,
    pub high: i64,
    pub snapshot: usize,
}

impl RangeQuery {
    pub fn new(low: i64, high: i64) -> Result<Self, String> {
        Self::with_snapshot(low, high, 0)
    }

    pub fn with_snapshot(low: i64, high: i64, snapshot: usize) -> Result<Self, String> {
        if high < low {
            return Err(format!("an empty range: [{low}, {high}]"));
        }
        Ok(Self {
            low,
            high,
            snapshot,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    pub count: Option<i64>,
    pub epsilon_spent: f64,
    pub refused: Option<String>,
    /// Inclusive window identifiers for a block-range answer.
    pub covered: Option<(usize, usize)>,
}

impl Answer {
    fn refused(reason: impl Into<String>) -> Self {
        Self {
            count: None,
            epsilon_spent: 0.0,
            refused: Some(reason.into()),
            covered: None,
        }
    }
}

/// Count eligible makers in an asker-selected price range and charge only the asker.
pub fn answer_range_query(
    quotes: &[i64],
    query: &RangeQuery,
    epsilon: f64,
    asker: &mut EntityAccountant,
    rng: &mut PyRandom,
) -> Result<Answer, String> {
    answer_range_query_with_eligibility(quotes, query, epsilon, asker, rng, None)
}

pub fn answer_range_query_with_eligibility(
    quotes: &[i64],
    query: &RangeQuery,
    epsilon: f64,
    asker: &mut EntityAccountant,
    rng: &mut PyRandom,
    eligible: Option<&[bool]>,
) -> Result<Answer, String> {
    if !asker.can_spend(epsilon) {
        return Ok(Answer::refused("the asker's query budget is spent"));
    }
    let eligible = match eligible {
        Some(flags) if flags.len() != quotes.len() => {
            return Err("one eligibility flag per quote".to_string())
        }
        Some(flags) => flags,
        None => &[],
    };
    asker.spend(epsilon);
    let true_count = quotes
        .iter()
        .enumerate()
        .filter(|(index, quote)| {
            (eligible.is_empty() || eligible[*index])
                && query.low <= **quote
                && **quote <= query.high
        })
        .count() as i64;
    let noisy = true_count + discrete_laplace(epsilon, SENSITIVITY as f64, rng);
    Ok(Answer {
        count: Some(noisy.max(0)),
        epsilon_spent: epsilon,
        refused: None,
        covered: None,
    })
}

/// The answer's uncertainty in entities.
pub fn noise_scale(epsilon: f64) -> f64 {
    SENSITIVITY as f64 / epsilon
}

pub fn questions_affordable(total: f64, epsilon: f64) -> Result<u64, String> {
    if epsilon <= 0.0 {
        return Err("a question at zero epsilon is a question that is free".to_string());
    }
    Ok((total / epsilon).floor() as u64)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pricing {
    pub base: f64,
    pub steepness: f64,
    pub epsilon_max: f64,
}

impl Default for Pricing {
    fn default() -> Self {
        Self {
            base: 1.0,
            steepness: 0.5,
            epsilon_max: 40.0,
        }
    }
}

impl Pricing {
    /// `base * expm1(steepness * epsilon)`.
    pub fn total_for(&self, epsilon: f64) -> Result<f64, String> {
        if epsilon < 0.0 {
            return Err("negative epsilon is not a purchase".to_string());
        }
        if epsilon > self.epsilon_max {
            return Err(format!(
                "{epsilon} is past the ceiling of {}; the ceiling is not for sale",
                self.epsilon_max
            ));
        }
        Ok(self.base * (self.steepness * epsilon).exp_m1())
    }

    pub fn price(&self, spent: f64, epsilon: f64) -> Result<f64, String> {
        Ok(self.total_for(spent + epsilon)? - self.total_for(spent)?)
    }

    pub fn affordable(&self, spent: f64, purse: f64, epsilon: f64) -> bool {
        self.price(spent, epsilon).is_ok_and(|price| price <= purse)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRangeQuery {
    pub from_block: usize,
    pub to_block: usize,
}

impl BlockRangeQuery {
    pub fn new(from_block: usize, to_block: usize) -> Result<Self, String> {
        if to_block < from_block {
            return Err(format!("an empty range: [{from_block}, {to_block}]"));
        }
        Ok(Self {
            from_block,
            to_block,
        })
    }
}

/// How far a query must lag the block currently being built.
pub const DEFAULT_SETTLEMENT_LAG: usize = 1_200;

/// Sensitivity of counting request events instead of distinct entities.
pub fn event_count_sensitivity(windows_covered: usize, cap: i64) -> Result<i64, String> {
    if cap < 0 {
        return Err("a negative range or a negative cap is not a question".to_string());
    }
    Ok(windows_covered as i64 * cap)
}

/// Windows wholly contained by an asker-selected public block range.
pub fn windows_in_range<'a>(
    windows: &'a [WindowObservation],
    query: &BlockRangeQuery,
) -> Vec<&'a WindowObservation> {
    windows
        .iter()
        .filter(|window| window.start_step >= query.from_block && window.end_step <= query.to_block)
        .collect()
}

/// Count distinct requesting entities over wholly covered windows.
pub fn answer_block_range_query(
    windows: &[WindowObservation],
    query: &BlockRangeQuery,
    epsilon: f64,
    asker: &mut EntityAccountant,
    rng: &mut PyRandom,
) -> Answer {
    // This compatibility entry point evaluates a finalized historical range.
    // Deployments that enforce chain recency call `answer_block_range_query_at`
    // with an observed height; an explicitly unknown height must fail closed.
    answer_block_range_query_at(
        windows,
        query,
        epsilon,
        asker,
        rng,
        Some(usize::MAX),
        DEFAULT_SETTLEMENT_LAG,
    )
}

pub fn answer_block_range_query_at(
    windows: &[WindowObservation],
    query: &BlockRangeQuery,
    epsilon: f64,
    asker: &mut EntityAccountant,
    rng: &mut PyRandom,
    now: Option<usize>,
    lag: usize,
) -> Answer {
    let Some(now) = now else {
        return Answer::refused("the range ends inside the last unknown blocks");
    };
    if query.to_block > now.saturating_sub(lag) {
        return Answer::refused(format!("the range ends inside the last {lag} blocks"));
    }
    if !asker.can_spend(epsilon) {
        return Answer::refused("the asker's query budget is spent");
    }

    let covered = windows_in_range(windows, query);
    if covered.is_empty() {
        return Answer::refused("no whole window lies inside the range");
    }

    asker.spend(epsilon);
    let entities: BTreeSet<usize> = covered
        .iter()
        .flat_map(|window| window.requests_by_entity.keys().copied())
        .collect();
    let noisy = entities.len() as i64 + discrete_laplace(epsilon, SENSITIVITY as f64, rng);
    Answer {
        count: Some(noisy.max(0)),
        epsilon_spent: epsilon,
        refused: None,
        covered: Some((covered[0].window, covered[covered.len() - 1].window)),
    }
}

pub fn expected_distinct(
    enrolled: i64,
    appearance_rate: f64,
    windows_covered: i64,
) -> Result<f64, String> {
    if enrolled < 0 || appearance_rate < 0.0 || windows_covered < 0 {
        return Err("negative enrolment, rate or span".to_string());
    }
    Ok(enrolled as f64 * -(-appearance_rate * windows_covered as f64).exp_m1())
}

/// Inclusive lower/upper range widths worth buying.
pub fn informative_span(
    enrolled: i64,
    appearance_rate: f64,
    epsilon: f64,
) -> Result<(i64, i64), String> {
    informative_span_with_saturation(enrolled, appearance_rate, epsilon, 0.95)
}

pub fn informative_span_with_saturation(
    enrolled: i64,
    appearance_rate: f64,
    epsilon: f64,
    saturation: f64,
) -> Result<(i64, i64), String> {
    if appearance_rate <= 0.0 {
        return Err("an entity that never appears has no span".to_string());
    }
    let floor = noise_scale(epsilon);
    let mut lower = 1;
    while lower < 10_000 && expected_distinct(enrolled, appearance_rate, lower)? < floor {
        lower += 1;
    }
    let upper = (-(1.0 - saturation).ln() / appearance_rate).ceil() as i64;
    Ok((lower, upper))
}
