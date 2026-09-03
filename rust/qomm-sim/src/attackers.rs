//! The adversaries the study scores, each given only what its arm leaks.
//!
//! Never report raw accuracy alone. In a set where most (entity, window) pairs
//! are inactive, always answering "inactive" already scores well, so every
//! attacker reports AUC and the advantage over the base rate, and the probing
//! attackers report how many probes they needed.
//!
//! The headline metric is deliberately narrow:
//!
//! > did entity *e* make a request in window *w*, given that entity *e* settled
//! > nothing in window *w*
//!
//! because that is exactly what the design claims. Executed trades stay visible
//! in every arm, so an evaluation that mixed them in would flatter the design.

use std::collections::{BTreeMap, BTreeSet};

use crate::deterministic_random::DeterministicRng;
use crate::engine::{ArmResult, ProbeResult};
use crate::market::{size_bucket, PricePath, SimConfig};

/// Rank-based AUC with ties averaged.
///
/// Ties matter more here than usual: a query-oblivious arm leaves an empty
/// channel, so *every* score ties, and any tie-breaking that used input order
/// would report leakage that does not exist.
pub fn auc(scores: &[f64], labels: &[u8]) -> Option<f64> {
    let n_pos = labels.iter().filter(|l| **l == 1).count();
    let n_neg = labels.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return None;
    }
    let mut pairs: Vec<(f64, u8)> = scores.iter().copied().zip(labels.iter().copied()).collect();
    pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().then(a.1.cmp(&b.1)));

    let (mut rank, mut rank_sum, mut index) = (1usize, 0.0f64, 0usize);
    while index < pairs.len() {
        let mut stop = index;
        while stop + 1 < pairs.len() && pairs[stop + 1].0 == pairs[index].0 {
            stop += 1;
        }
        let avg_rank = (rank + (rank + (stop - index))) as f64 / 2.0;
        for pair in &pairs[index..=stop] {
            if pair.1 == 1 {
                rank_sum += avg_rank;
            }
        }
        rank += stop - index + 1;
        index = stop + 1;
    }
    Some((rank_sum - (n_pos * (n_pos + 1)) as f64 / 2.0) / (n_pos * n_neg) as f64)
}

/// Detection rate at a fixed false-positive rate.
///
/// Ties are resolved by interpolation rather than by input order: a threshold
/// cannot separate examples that share a score, so counting the positives in a
/// tie group first would report a rate no real attacker can reach.
pub fn tpr_at_fpr(scores: &[f64], labels: &[u8], target_fpr: f64) -> Option<f64> {
    let n_pos = labels.iter().filter(|l| **l == 1).count();
    let n_neg = labels.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return None;
    }
    let mut order: Vec<(f64, u8)> = scores.iter().copied().zip(labels.iter().copied()).collect();
    order.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.cmp(&b.1)));

    let (mut tp, mut fp, mut best, mut index) = (0usize, 0usize, 0.0f64, 0usize);
    while index < order.len() {
        let mut stop = index;
        while stop + 1 < order.len() && order[stop + 1].0 == order[index].0 {
            stop += 1;
        }
        let group_pos = order[index..=stop].iter().filter(|p| p.1 == 1).count();
        let group_neg = (stop - index + 1) - group_pos;
        if (fp + group_neg) as f64 <= target_fpr * n_neg as f64 {
            tp += group_pos;
            fp += group_neg;
            best = best.max(tp as f64 / n_pos as f64);
        } else {
            // admit the fraction of the tie group the budget allows
            let room = target_fpr * n_neg as f64 - fp as f64;
            if group_neg > 0 && room > 0.0 {
                let share = room / group_neg as f64;
                best = best.max((tp as f64 + share * group_pos as f64) / n_pos as f64);
            }
            break;
        }
        index = stop + 1;
    }
    Some(best)
}

#[derive(Clone, Debug)]
pub struct AttackReport {
    pub name: &'static str,
    pub target: &'static str,
    pub auc: Option<f64>,
    pub tpr_at_5pct_fpr: Option<f64>,
    pub base_rate: f64,
    pub advantage: Option<f64>,
    pub n_examples: usize,
    pub extra: BTreeMap<&'static str, Option<f64>>,
}

fn window_of(step: usize, cfg: &SimConfig) -> usize {
    step / cfg.window_steps
}

/// One adversary, scored the same way as every other.
///
/// Most of the attackers share a shape: build a score and a label for each
/// example, then report AUC, the detection rate at a fixed false-positive rate,
/// and the advantage over the base rate. That reporting was written out in each
/// of them, so a change to how detection is reported had to be made everywhere
/// and could be made almost everywhere.
///
/// An implementor supplies `score_population`; everything after it is here.
pub trait Attack {
    fn name(&self) -> &'static str;
    fn target(&self) -> &'static str;
    /// One entry per example this attacker sees.
    fn score_population(&mut self, result: &ArmResult, cfg: &SimConfig) -> (Vec<f64>, Vec<u8>);
    /// Anything reported beyond the shared statistics.
    fn extra(&self, _result: &ArmResult, _cfg: &SimConfig) -> BTreeMap<&'static str, Option<f64>> {
        BTreeMap::new()
    }

    fn run(&mut self, result: &ArmResult, cfg: &SimConfig) -> AttackReport {
        let (scores, labels) = self.score_population(result, cfg);
        let base = if labels.is_empty() {
            0.0
        } else {
            labels.iter().filter(|l| **l == 1).count() as f64 / labels.len() as f64
        };
        let value = auc(&scores, &labels);
        AttackReport {
            name: self.name(),
            target: self.target(),
            auc: value,
            tpr_at_5pct_fpr: tpr_at_fpr(&scores, &labels, 0.05),
            base_rate: base,
            advantage: value.map(|v| (v - 0.5).abs() * 2.0),
            n_examples: labels.len(),
            extra: self.extra(result, cfg),
        }
    }
}

/// Shared by the attackers that ask the design's own question.
///
/// The population is deliberately narrow --- only (entity, window) pairs where
/// the entity settled nothing --- because that is exactly what the design claims
/// to hide. Including settled pairs would flatter it, since settlements are
/// visible in every arm.
pub trait UnsettledRequestAttack {
    /// A score attached to a whole window, such as a published aggregate.
    fn window_score(&self, _result: &ArmResult, _cfg: &SimConfig) -> BTreeMap<usize, f64> {
        BTreeMap::new()
    }
    /// A score attached to one (entity, window) pair.
    fn pair_score(&self, _key: (usize, usize)) -> f64 {
        0.0
    }
    /// Anything that has to be computed once before scoring begins.
    fn prepare(&mut self, _result: &ArmResult, _cfg: &SimConfig) {}

    fn score_unsettled(&mut self, result: &ArmResult, cfg: &SimConfig) -> (Vec<f64>, Vec<u8>) {
        self.prepare(result, cfg);
        let (requested, settled) = ground_truth(result, cfg);
        let by_window = self.window_score(result, cfg);
        let n_windows = (cfg.steps / cfg.window_steps).max(1);
        let (mut scores, mut labels) = (Vec::new(), Vec::new());
        for entity in 0..cfg.n_entities {
            for window in 0..n_windows {
                let key = (entity, window);
                if settled.contains(&key) {
                    continue;
                }
                scores.push(self.pair_score(key) + by_window.get(&window).copied().unwrap_or(0.0));
                labels.push(u8::from(requested.contains(&key)));
            }
        }
        (scores, labels)
    }
}

type EntityWindowSet = BTreeSet<(usize, usize)>;

/// `(entity, window) -> requested?` and `-> settled?`
fn ground_truth(result: &ArmResult, cfg: &SimConfig) -> (EntityWindowSet, EntityWindowSet) {
    let mut requested = BTreeSet::new();
    let mut settled = BTreeSet::new();
    for row in &result.truth {
        let key = (row.entity, window_of(row.step, cfg));
        requested.insert(key);
        if row.executed {
            settled.insert(key);
        }
    }
    (requested, settled)
}

/// Wallets whose controlling entity the attacker has already de-anonymised.
///
/// Drawn at random rather than at a fixed stride. A stride quantises the
/// fraction, and one sharing a factor with `wallets_per_entity` picks the same
/// slot inside every entity --- so it de-anonymises half the wallets and *all*
/// of the firms. The attack keys on the entity, so entity coverage is what
/// `rho` actually buys.
pub fn linked_wallets(cfg: &SimConfig, rho: f64, seed: u64) -> BTreeSet<usize> {
    let n_wallets = cfg.n_entities * cfg.wallets_per_entity;
    if rho <= 0.0 {
        return BTreeSet::new();
    }
    if rho >= 1.0 {
        return (0..n_wallets).collect();
    }
    let take = crate::market::round_half_even(rho * n_wallets as f64) as usize;
    DeterministicRng::new(seed)
        .sample(n_wallets, take)
        .into_iter()
        .collect()
}

/// Attacker 1: whatever the protocol leaks at request time, plus the releases.
///
/// Two channels feed one score. The direct channel is a request or settlement
/// seen from a wallet the attacker has already de-anonymised; the aggregate
/// channel is how surprising the published count for that window was. The
/// aggregate is weighted a thousandth of the direct one because it cannot
/// identify anybody by itself --- it only breaks ties.
pub struct PassiveObserver {
    pub rho: f64,
    pub seed: u64,
    linked: BTreeSet<usize>,
    seen: BTreeSet<(usize, usize)>,
}

impl PassiveObserver {
    pub fn new(rho: f64, seed: u64) -> Self {
        PassiveObserver {
            rho,
            seed,
            linked: BTreeSet::new(),
            seen: BTreeSet::new(),
        }
    }
}

impl UnsettledRequestAttack for PassiveObserver {
    fn prepare(&mut self, result: &ArmResult, cfg: &SimConfig) {
        self.linked = linked_wallets(cfg, self.rho, self.seed);
        self.seen.clear();
        for obs in &result.observations {
            if self.linked.contains(&obs.wallet) {
                self.seen.insert((obs.entity, window_of(obs.step, cfg)));
            }
        }
        // settlements are on chain in every arm
        for stl in &result.settlements {
            if self.linked.contains(&stl.wallet) {
                self.seen.insert((stl.entity, window_of(stl.step, cfg)));
            }
        }
    }

    fn pair_score(&self, key: (usize, usize)) -> f64 {
        f64::from(u8::from(self.seen.contains(&key)))
    }

    fn window_score(&self, result: &ArmResult, _cfg: &SimConfig) -> BTreeMap<usize, f64> {
        let mut out = BTreeMap::new();
        for release in result.releases.iter().filter(|r| r.published) {
            match release.mode {
                "C_dp" => {
                    let scale = release.fields.noise_scale_requests.max(1.0);
                    out.insert(
                        release.window,
                        0.001 * (release.fields.noisy_requests as f64 / scale),
                    );
                }
                "B_threshold" => {
                    out.insert(release.window, 0.001 * 0.5);
                }
                _ => {}
            }
        }
        out
    }
}

impl Attack for PassiveObserver {
    fn name(&self) -> &'static str {
        "A1_passive_observer"
    }
    fn target(&self) -> &'static str {
        "unsettled_request_existence"
    }
    fn score_population(&mut self, result: &ArmResult, cfg: &SimConfig) -> (Vec<f64>, Vec<u8>) {
        self.score_unsettled(result, cfg)
    }
    fn extra(&self, _result: &ArmResult, cfg: &SimConfig) -> BTreeMap<&'static str, Option<f64>> {
        [
            ("linkage_rho", Some(self.rho)),
            ("wallets_linked", Some(self.linked.len() as f64)),
            (
                "entities_covered",
                Some(
                    self.linked
                        .iter()
                        .map(|w| w / cfg.wallets_per_entity)
                        .collect::<BTreeSet<_>>()
                        .len() as f64,
                ),
            ),
        ]
        .into_iter()
        .collect()
    }
}

pub fn passive_observer(result: &ArmResult, cfg: &SimConfig, rho: f64, seed: u64) -> AttackReport {
    PassiveObserver::new(rho, seed).run(result, cfg)
}

/// Attacker 2: the difference between adjacent published windows.
///
/// Continual observation is where a per-window budget is supposed to bite, so
/// the attack that differences consecutive releases is the one that tests it.
#[derive(Default)]
pub struct WindowShiftObserver;

impl UnsettledRequestAttack for WindowShiftObserver {
    fn window_score(&self, result: &ArmResult, cfg: &SimConfig) -> BTreeMap<usize, f64> {
        let n_windows = (cfg.steps / cfg.window_steps).max(1);
        let published: BTreeMap<usize, &crate::disclosure::Release> = result
            .releases
            .iter()
            .filter(|r| r.published)
            .map(|r| (r.window, r))
            .collect();
        let mut delta = BTreeMap::new();
        let mut previous: Option<i64> = None;
        for window in 0..n_windows {
            let Some(release) = published.get(&window) else {
                continue;
            };
            if release.mode != "C_dp" {
                continue;
            }
            let current = release.fields.noisy_requests;
            if let Some(before) = previous {
                delta.insert(
                    window,
                    (current - before) as f64 / release.fields.noise_scale_requests.max(1.0),
                );
            }
            previous = Some(current);
        }
        delta
    }
}

impl Attack for WindowShiftObserver {
    fn name(&self) -> &'static str {
        "A2_window_shift"
    }
    fn target(&self) -> &'static str {
        "unsettled_request_existence"
    }
    fn score_population(&mut self, result: &ArmResult, cfg: &SimConfig) -> (Vec<f64>, Vec<u8>) {
        self.score_unsettled(result, cfg)
    }
}

pub fn window_shift_observer(result: &ArmResult, cfg: &SimConfig) -> AttackReport {
    WindowShiftObserver.run(result, cfg)
}

/// Attacker 3: reconstruct aggregate maker inventory from firm prices.
///
/// Query-obliviousness does not stop this: a firm price is exactly what the
/// protocol is designed to return. Only entity-level rate limits do.
pub fn probing_entity(result: &ArmResult, probe_budget: usize) -> AttackReport {
    let available: Vec<&ProbeResult> = result
        .probe_results
        .iter()
        .filter(|p| p.best_ask.is_some() && p.best_bid.is_some())
        .collect();
    // Spend the allowance evenly over the horizon; a prefix would confound the
    // budget with the period observed.
    let rows: Vec<&ProbeResult> = if probe_budget >= available.len() {
        available.clone()
    } else {
        let stride = available.len() as f64 / probe_budget as f64;
        (0..probe_budget)
            .map(|k| available[(k as f64 * stride) as usize])
            .collect()
    };
    let mut extra: BTreeMap<&'static str, Option<f64>> =
        [("probe_budget", Some(probe_budget as f64))]
            .into_iter()
            .collect();
    if rows.len() < 4 {
        // four points is the floor at which a correlation means anything
        return AttackReport {
            name: "A3_probing_entity",
            target: "maker_inventory",
            auc: None,
            tpr_at_5pct_fpr: None,
            base_rate: 0.0,
            advantage: None,
            n_examples: rows.len(),
            extra,
        };
    }

    // The midpoint of a two-sided quote cancels the half spread, leaving the
    // inventory skew the maker applied.
    let skew: Vec<f64> = rows
        .iter()
        .map(|p| 0.5 * (p.best_ask.unwrap() + p.best_bid.unwrap()) as f64 - p.ref_mid as f64)
        .collect();
    let net: Vec<f64> = rows.iter().map(|p| p.true_net_inventory as f64).collect();
    extra.insert(
        "net_inventory_corr_from_best_quote",
        pearson(&skew, &net).map(f64::abs),
    );

    // A plain protocol answers per maker, so the same estimator applies per maker.
    let per_mm = rows[0].per_mm_quotes.as_ref().and_then(|first| {
        let mut values = Vec::new();
        for mm_id in first.keys() {
            let series: Vec<(f64, f64)> = rows
                .iter()
                .filter_map(|p| {
                    let q = p.per_mm_quotes.as_ref()?.get(mm_id)?;
                    Some((
                        0.5 * (q.0 + q.1) as f64 - p.ref_mid as f64,
                        *p.per_mm_inventory.get(mm_id).unwrap_or(&0) as f64,
                    ))
                })
                .collect();
            if series.len() < 4 {
                continue;
            }
            let (xs, ys): (Vec<f64>, Vec<f64>) = series.into_iter().unzip();
            if let Some(v) = pearson(&xs, &ys) {
                values.push(v.abs());
            }
        }
        if values.is_empty() {
            None
        } else {
            Some(crate::fsum::fsum(values.iter().copied()) / values.len() as f64)
        }
    });
    extra.insert("own_inventory_corr_from_per_mm_quotes", per_mm);

    AttackReport {
        name: "A3_probing_entity",
        target: "maker_inventory",
        auc: None,
        tpr_at_5pct_fpr: None,
        base_rate: 0.0,
        advantage: None,
        n_examples: rows.len(),
        extra,
    }
}

/// Direction and size-bucket recovery for requests that never executed.
///
/// This is what separates plain RFQ, RFM and RFS from each other. RFM already
/// hides direction and RFS already hides size without any cryptography, so
/// those savings must not be credited to the MPC design. An attacker that never
/// sees the request falls back on the population prior, which is the figure
/// reported for the query-oblivious arms.
pub fn pretrade_attributes(result: &ArmResult, cfg: &SimConfig) -> AttackReport {
    let _ = cfg;
    let unsettled: Vec<_> = result.truth.iter().filter(|r| !r.executed).collect();
    if unsettled.is_empty() {
        return AttackReport {
            name: "A1b_pretrade_attributes",
            target: "direction_and_size",
            auc: None,
            tpr_at_5pct_fpr: None,
            base_rate: 0.0,
            advantage: None,
            n_examples: 0,
            extra: BTreeMap::new(),
        };
    }
    let seen: BTreeMap<(usize, usize), &crate::engine::RequestObservation> = result
        .observations
        .iter()
        .map(|o| ((o.step, o.wallet), o))
        .collect();

    let mut dir_counts = [0usize; 2];
    let mut bucket_counts = [0usize; 3];
    for row in &unsettled {
        dir_counts[row.direction as usize] += 1;
        bucket_counts[size_bucket(row.size)] += 1;
    }
    let total = unsettled.len() as f64;
    let prior_dir = *dir_counts.iter().max().unwrap() as f64 / total;
    let prior_bucket = *bucket_counts.iter().max().unwrap() as f64 / total;
    let majority_dir = dir_counts
        .iter()
        .enumerate()
        .max_by_key(|(_, c)| **c)
        .map(|(i, _)| i as u8)
        .unwrap();
    let majority_bucket = bucket_counts
        .iter()
        .enumerate()
        .max_by_key(|(_, c)| **c)
        .map(|(i, _)| i)
        .unwrap();

    let (mut dir_hits, mut bucket_hits) = (0usize, 0usize);
    for row in &unsettled {
        let obs = seen.get(&(row.step, row.wallet));
        let guessed_dir = obs.and_then(|o| o.direction).unwrap_or(majority_dir);
        if guessed_dir == row.direction {
            dir_hits += 1;
        }
        let guessed_bucket = obs
            .and_then(|o| o.size)
            .map(size_bucket)
            .unwrap_or(majority_bucket);
        if guessed_bucket == size_bucket(row.size) {
            bucket_hits += 1;
        }
    }

    AttackReport {
        name: "A1b_pretrade_attributes",
        target: "direction_and_size",
        auc: None,
        tpr_at_5pct_fpr: None,
        base_rate: prior_dir,
        advantage: None,
        n_examples: unsettled.len(),
        extra: [
            ("direction_accuracy", Some(dir_hits as f64 / total)),
            ("direction_prior", Some(prior_dir)),
            ("size_bucket_accuracy", Some(bucket_hits as f64 / total)),
            ("size_bucket_prior", Some(prior_bucket)),
        ]
        .into_iter()
        .collect(),
    }
}

pub const PROBE_BUDGETS: [usize; 10] = [4, 6, 8, 12, 16, 24, 32, 64, 128, 256];

/// How much probing does the inventory attack actually need?
pub fn probe_cost_curve(result: &ArmResult) -> BTreeMap<usize, (Option<f64>, Option<f64>)> {
    probe_cost_curve_with_budgets(result, &PROBE_BUDGETS)
}

pub fn probe_cost_curve_with_budgets(
    result: &ArmResult,
    budgets: &[usize],
) -> BTreeMap<usize, (Option<f64>, Option<f64>)> {
    budgets
        .iter()
        .map(|budget| {
            let report = probing_entity(result, *budget);
            (
                *budget,
                (
                    report
                        .extra
                        .get("net_inventory_corr_from_best_quote")
                        .copied()
                        .flatten(),
                    report
                        .extra
                        .get("own_inventory_corr_from_per_mm_quotes")
                        .copied()
                        .flatten(),
                ),
            )
        })
        .collect()
}

fn probes_needed(
    curve: &BTreeMap<usize, (Option<f64>, Option<f64>)>,
    net: bool,
    target: f64,
) -> Option<usize> {
    curve
        .iter()
        .find(|(_, (a, b))| {
            let value = if net { a } else { b };
            value.is_some_and(|v| v >= target)
        })
        .map(|(budget, _)| *budget)
}

/// Attacker 4: a wallet-level cap scales with wallet count; an entity cap does not.
pub fn colluding_wallets(
    result: &ArmResult,
    cfg: &SimConfig,
    wallet_limit: usize,
    entity_limit: usize,
) -> AttackReport {
    let n_windows = (cfg.steps / cfg.window_steps).max(1);
    let wallet_capped = wallet_limit * cfg.wallets_per_entity * n_windows;
    let entity_capped = entity_limit * n_windows;
    let curve = probe_cost_curve(result);
    let under_wallet = probing_entity(result, wallet_capped);
    let under_entity = probing_entity(result, entity_capped);
    AttackReport {
        name: "A4_colluding_wallets",
        target: "maker_inventory",
        auc: None,
        tpr_at_5pct_fpr: None,
        base_rate: 0.0,
        advantage: None,
        n_examples: result.probe_results.len().min(wallet_capped),
        extra: [
            ("probes_under_wallet_limit", Some(wallet_capped as f64)),
            ("probes_under_entity_limit", Some(entity_capped as f64)),
            (
                "corr_under_wallet_limit",
                under_wallet
                    .extra
                    .get("net_inventory_corr_from_best_quote")
                    .copied()
                    .flatten(),
            ),
            (
                "corr_under_entity_limit",
                under_entity
                    .extra
                    .get("net_inventory_corr_from_best_quote")
                    .copied()
                    .flatten(),
            ),
            (
                "probes_needed_net_corr_0.8",
                probes_needed(&curve, true, 0.8).map(|v| v as f64),
            ),
            (
                "probes_needed_per_mm_corr_0.8",
                probes_needed(&curve, false, 0.8).map(|v| v as f64),
            ),
        ]
        .into_iter()
        .collect(),
    }
}

/// Attacker 5: was this settled trade informed?
///
/// Settlements are visible in every arm, so this attack is unchanged by hiding
/// requests --- which is the reason to report it. It marks the boundary of what
/// the design claims.
pub struct ExternalInfoObserver<'a> {
    pub market: &'a dyn PricePath,
}

impl Attack for ExternalInfoObserver<'_> {
    fn name(&self) -> &'static str {
        "A5_external_info"
    }
    fn target(&self) -> &'static str {
        "settled_trade_was_informed"
    }
    fn score_population(&mut self, result: &ArmResult, cfg: &SimConfig) -> (Vec<f64>, Vec<u8>) {
        let informed: BTreeMap<(usize, usize), bool> = result
            .truth
            .iter()
            .map(|r| ((r.step, r.wallet), r.informed))
            .collect();
        let (mut scores, mut labels) = (Vec::new(), Vec::new());
        for stl in &result.settlements {
            let future =
                self.market.mid()[(stl.step + 20).min(cfg.steps)] - self.market.mid()[stl.step];
            // a buy just before a rise looks informed
            let signed_move = if stl.direction == 0 { future } else { -future };
            scores.push(signed_move as f64);
            labels.push(u8::from(
                informed
                    .get(&(stl.step, stl.wallet))
                    .copied()
                    .unwrap_or(false),
            ));
        }
        (scores, labels)
    }
}

pub fn external_info_observer(
    result: &ArmResult,
    cfg: &SimConfig,
    market: &dyn PricePath,
) -> AttackReport {
    ExternalInfoObserver { market }.run(result, cfg)
}

fn pearson(a: &[f64], b: &[f64]) -> Option<f64> {
    let n = a.len().min(b.len());
    if n < 3 {
        return None;
    }
    let (a, b) = (&a[..n], &b[..n]);
    // `statistics.fmean`, which is `fsum` then one division --- not a naive
    // sum. The difference is one unit in the last place, and it reached the
    // reported correlations.
    let (ma, mb) = (
        crate::fsum::fsum(a.iter().copied()) / n as f64,
        crate::fsum::fsum(b.iter().copied()) / n as f64,
    );
    // means above are `statistics.fmean`, which is `fsum`. Routing all five
    // through the more accurate of the two would be a different function from
    // the one being ported.
    let num = crate::fsum::nsum(a.iter().zip(b).map(|(x, y)| (x - ma) * (y - mb)));
    let da = crate::fsum::nsum(a.iter().map(|x| (x - ma).powi(2))).sqrt();
    let db = crate::fsum::nsum(b.iter().map(|y| (y - mb).powi(2))).sqrt();
    if da == 0.0 || db == 0.0 {
        return None;
    }
    Some(num / (da * db))
}
