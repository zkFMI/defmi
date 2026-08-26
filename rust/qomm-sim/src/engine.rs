//! One simulation arm = (request protocol) x (disclosure mechanism).
//!
//! The protocol decides *who observes a request*; the disclosure mechanism
//! decides *what the public learns afterwards*. Both vary independently, which
//! is what lets the study attribute an effect to one or the other.
//!
//! What a maker or an outside observer sees at request time:
//!
//! ```text
//! plain_rfq  asset, size, direction, wallet, time   (every queried maker)
//! plain_rfm  asset, size, wallet, time              (direction withheld)
//! plain_rfs  asset, wallet, request window          (size withheld)
//! qomm_*     nothing --- the request never reaches a maker
//! ```
//!
//! A settled trade is visible in every arm. The arms therefore differ in what
//! they reveal about requests that did *not* execute, and about direction before
//! execution --- which is exactly what the detection metric scores.

use std::collections::BTreeMap;

use crate::disclosure::{Disclosure, PublicSignal, Release, WindowObservation};
use crate::market::{size_bucket, MarketMaker, PricePath, Request, SimConfig};
use crate::pyrandom::PyRandom;

pub const PLAIN_PROTOCOLS: [&str; 3] = ["plain_rfq", "plain_rfm", "plain_rfs"];
pub const QOMM_PROTOCOLS: [&str; 3] = ["qomm_rfq", "qomm_rfm", "qomm_rfs"];
pub const MARKOUT_HORIZONS: [(&str, usize); 3] = [
    ("markout_50ms", 1),
    ("markout_1s", 20),
    ("markout_10s", 200),
];

const PRIOR_HALF_TICKS: f64 = 26.0;
const PRIOR_HALF_SD: f64 = 14.0;
const TIGHT_HALF_SD: f64 = 5.0;
const USER_SLACK_TICKS: i64 = 6;

/// What a maker learned at request time, if anything.
#[derive(Clone, Copy, Debug)]
pub struct RequestObservation {
    pub step: usize,
    pub wallet: usize,
    pub entity: usize,
    pub size: Option<i64>,
    pub direction: Option<u8>,
    pub executed: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Settlement {
    pub step: usize,
    pub wallet: usize,
    pub entity: usize,
    pub size: i64,
    pub direction: u8,
    pub price: i64,
    pub mm_id: usize,
}

/// A rate-limited two-sided probe an attacker is allowed to send.
///
/// Both sides at one fixed size, because the midpoint of a two-sided quote
/// cancels the half spread and leaves exactly the inventory skew:
/// `(ask + bid)/2 - m = invcoef * inv`. That is the sharpest inventory
/// estimator a probing entity has, and it works in every arm by design.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub step: usize,
    pub size: i64,
    pub wallet: usize,
    pub entity: usize,
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub step: usize,
    pub size: i64,
    pub best_ask: Option<i64>,
    pub best_bid: Option<i64>,
    /// Only the plain protocols leak this.
    pub per_mm_quotes: Option<BTreeMap<usize, (i64, i64)>>,
    pub per_mm_inventory: BTreeMap<usize, i64>,
    pub true_net_inventory: i64,
    pub ref_mid: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct Truth {
    pub step: usize,
    pub entity: usize,
    pub wallet: usize,
    pub size: i64,
    pub direction: u8,
    pub executed: bool,
    pub informed: bool,
}

pub struct ArmResult {
    pub protocol: String,
    pub disclosure: &'static str,
    pub requests: usize,
    pub fills: u64,
    pub no_quote: u64,
    pub rejected: u64,
    pub user_cost_ticks: Vec<f64>,
    pub mm_pnl: BTreeMap<usize, f64>,
    pub mm_markouts: BTreeMap<&'static str, Vec<f64>>,
    pub quote_continuation: f64,
    pub releases: Vec<Release>,
    pub release_errors: BTreeMap<&'static str, Vec<f64>>,
    pub suppression_rate: f64,
    pub observations: Vec<RequestObservation>,
    pub settlements: Vec<Settlement>,
    pub truth: Vec<Truth>,
    pub windows: Vec<WindowObservation>,
    pub epsilon_spent_max: f64,
    pub probe_results: Vec<ProbeResult>,
}

impl ArmResult {
    pub fn fill_rate(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            self.fills as f64 / self.requests as f64
        }
    }
    pub fn mm_pnl_total(&self) -> f64 {
        self.mm_pnl.values().sum()
    }
    pub fn mm_pnl_per_fill(&self) -> Option<f64> {
        if self.fills == 0 {
            None
        } else {
            Some(self.mm_pnl_total() / self.fills as f64)
        }
    }
    pub fn user_cost_median(&self) -> Option<f64> {
        median(&self.user_cost_ticks)
    }
    pub fn markout_mean(&self, key: &str) -> Option<f64> {
        let values = self.mm_markouts.get(key)?;
        if values.is_empty() {
            None
        } else {
            Some(crate::fsum::nsum(values.iter().copied()) / values.len() as f64)
        }
    }
}

fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = ordered.len() / 2;
    Some(if ordered.len() % 2 == 1 {
        ordered[mid]
    } else {
        0.5 * (ordered[mid - 1] + ordered[mid])
    })
}

/// A maker's estimate of the informed fraction, from its own flow plus whatever
/// the venue published.
#[derive(Clone, Copy, Debug)]
pub struct BeliefState {
    prior: f64,
    prior_var: f64,
    adverse: f64,
    count: f64,
}

impl Default for BeliefState {
    fn default() -> Self {
        BeliefState {
            prior: 0.30,
            prior_var: 0.05,
            adverse: 0.0,
            count: 0.0,
        }
    }
}

impl BeliefState {
    pub fn observe_fill(&mut self, adverse: bool) {
        // exponential forgetting keeps the estimate responsive
        const DECAY: f64 = 0.98;
        self.adverse = DECAY * self.adverse + f64::from(adverse);
        self.count = DECAY * self.count + 1.0;
    }

    fn own_estimate(&self) -> (f64, f64) {
        if self.count < 1.0 {
            return (self.prior, self.prior_var);
        }
        let phi = self.adverse / self.count;
        (phi, (phi * (1.0 - phi) / self.count).max(1e-3))
    }

    /// Inverse-variance weighting: a public signal moves the estimate only to
    /// the extent it is more precise than the maker's own flow. This is the
    /// channel the disclosure results are about, and why a biased statistic is
    /// worse than no statistic rather than merely useless.
    pub fn combined(&self, public: PublicSignal) -> f64 {
        let (own, own_var) = self.own_estimate();
        match public {
            (None, _) => own,
            (Some(_), v) if !v.is_finite() => own,
            (Some(p), pub_var) => {
                let (w_own, w_pub) = (1.0 / own_var, 1.0 / pub_var);
                (own * w_own + p * w_pub) / (w_own + w_pub)
            }
        }
    }
}

/// What one protocol lets a market maker learn at request time.
///
/// This used to be a four-way match in the middle of the arm loop, which put
/// the answer to "what does RFM hide?" a hundred lines from the answer to "what
/// does RFS hide?". Each protocol is now one small type, and adding a protocol
/// is adding a type rather than editing the loop.
pub trait LeakagePolicy {
    fn name(&self) -> &'static str;
    /// The record a maker keeps, or `None` when the request never reaches one.
    fn observe(&self, step: usize, req: &Request) -> Option<RequestObservation>;
    /// Whether a probe's per-maker answers are visible, which only the plain
    /// protocols make so.
    fn leaks_per_maker_quotes(&self) -> bool {
        false
    }
}

fn observation(
    step: usize,
    req: &Request,
    size: Option<i64>,
    direction: Option<u8>,
) -> Option<RequestObservation> {
    Some(RequestObservation {
        step,
        wallet: req.wallet,
        entity: req.entity,
        size,
        direction,
        executed: false,
    })
}

/// RFQ: every queried maker sees the asset, the size and the direction.
pub struct FullRequestVisible;
impl LeakagePolicy for FullRequestVisible {
    fn name(&self) -> &'static str {
        "plain_rfq"
    }
    fn observe(&self, step: usize, req: &Request) -> Option<RequestObservation> {
        observation(step, req, Some(req.size), Some(req.direction))
    }
    fn leaks_per_maker_quotes(&self) -> bool {
        true
    }
}

/// RFM: the maker quotes both sides, so it learns size but not direction.
pub struct DirectionWithheld;
impl LeakagePolicy for DirectionWithheld {
    fn name(&self) -> &'static str {
        "plain_rfm"
    }
    fn observe(&self, step: usize, req: &Request) -> Option<RequestObservation> {
        observation(step, req, Some(req.size), None)
    }
    fn leaks_per_maker_quotes(&self) -> bool {
        true
    }
}

/// RFS: a stream, so the maker learns that this wallet is active and no more.
pub struct SizeWithheld;
impl LeakagePolicy for SizeWithheld {
    fn name(&self) -> &'static str {
        "plain_rfs"
    }
    fn observe(&self, step: usize, req: &Request) -> Option<RequestObservation> {
        observation(step, req, None, None)
    }
    fn leaks_per_maker_quotes(&self) -> bool {
        true
    }
}

/// The query-oblivious arms: the request never reaches a maker at all.
pub struct NothingReaches;
impl LeakagePolicy for NothingReaches {
    fn name(&self) -> &'static str {
        "qomm"
    }
    fn observe(&self, _step: usize, _req: &Request) -> Option<RequestObservation> {
        None
    }
}

pub fn leakage_policy(protocol: &str) -> Box<dyn LeakagePolicy> {
    match protocol {
        "plain_rfq" => Box::new(FullRequestVisible),
        "plain_rfm" => Box::new(DirectionWithheld),
        "plain_rfs" => Box::new(SizeWithheld),
        _ => Box::new(NothingReaches),
    }
}

/// What the user believes the best achievable half spread is.
fn user_half_estimate(name: &str, release: Option<&Release>) -> (f64, f64) {
    let Some(release) = release else {
        return (PRIOR_HALF_TICKS, PRIOR_HALF_SD);
    };
    match name {
        "B_threshold" => {
            if release.published {
                (PRIOR_HALF_TICKS * 0.75, TIGHT_HALF_SD * 1.6)
            } else {
                (PRIOR_HALF_TICKS * 1.15, PRIOR_HALF_SD)
            }
        }
        "C_dp" if release.published => match release.fields.fill_rate {
            None => (PRIOR_HALF_TICKS, PRIOR_HALF_SD),
            // a high observed fill rate implies quotes are close to the mid
            Some(rate) => (
                PRIOR_HALF_TICKS * (1.35 - 0.7 * rate.clamp(0.0, 1.0)),
                TIGHT_HALF_SD,
            ),
        },
        _ => (PRIOR_HALF_TICKS, PRIOR_HALF_SD),
    }
}

pub struct ArmOptions {
    pub protocol: String,
    pub seed: u64,
    pub probes: Vec<Probe>,
    pub reactive: bool,
    pub max_retries: u32,
    pub retry_delay: usize,
}

/// The public signal visible to one maker. A subscriber-only disclosure must
/// not silently become venue-wide inside quote or probe pricing.
pub fn public_for(
    disclosure: &Disclosure,
    release: Option<&Release>,
    mm_id: usize,
) -> PublicSignal {
    match release {
        Some(release) if disclosure.reaches(mm_id) => disclosure.public_signal(release),
        _ => (None, f64::INFINITY),
    }
}

impl ArmOptions {
    pub fn new(protocol: &str, seed: u64) -> Self {
        ArmOptions {
            protocol: protocol.to_string(),
            seed,
            probes: Vec::new(),
            reactive: false,
            max_retries: 2,
            retry_delay: 40,
        }
    }
}

/// The counters a disclosure window is built from.
///
/// They were loose locals reset by hand at the boundary, which is exactly the
/// shape where one gets forgotten. Keeping them together makes the reset one
/// statement and the window's contents one value.
#[derive(Default)]
struct WindowState {
    requests: BTreeMap<usize, i64>,
    volume: BTreeMap<usize, i64>,
    signed: BTreeMap<usize, i64>,
    fills_by_entity: BTreeMap<usize, i64>,
    fills: i64,
    total: i64,
    no_quote: i64,
    fills_by_bucket: [i64; 3],
    requests_by_bucket: [i64; 3],
    start: usize,
}

impl WindowState {
    fn saw_request(&mut self, req: &Request, bucket: usize) {
        self.total += 1;
        self.requests_by_bucket[bucket] += 1;
        *self.requests.entry(req.entity).or_insert(0) += 1;
    }

    fn saw_no_quote(&mut self) {
        self.no_quote += 1;
    }

    fn saw_fill(&mut self, req: &Request, bucket: usize, signed: i64) {
        self.fills += 1;
        self.fills_by_bucket[bucket] += 1;
        *self.fills_by_entity.entry(req.entity).or_insert(0) += 1;
        *self.volume.entry(req.entity).or_insert(0) += req.size;
        *self.signed.entry(req.entity).or_insert(0) += signed;
    }

    fn observation(
        &self,
        window: usize,
        end_step: usize,
        makers_in_band: i64,
        lots_in_band: i64,
    ) -> WindowObservation {
        WindowObservation {
            window,
            start_step: self.start,
            end_step,
            requests_by_entity: self.requests.clone(),
            volume_by_entity: self.volume.clone(),
            signed_volume_by_entity: self.signed.clone(),
            fills_by_entity: self.fills_by_entity.clone(),
            fills: self.fills,
            requests: self.total,
            no_quote: self.no_quote,
            liquidity_lots_in_band: lots_in_band,
            makers_in_band,
            fills_by_bucket: self.fills_by_bucket,
            requests_by_bucket: self.requests_by_bucket,
        }
    }
}

/// One arm's mutable state, so the loop can be read a step at a time.
///
/// `run_arm` was one long function holding twenty locals, which is more than a
/// reader can carry while deciding whether a change is safe. The state lives
/// here and each method answers one question: who saw it, what did it cost, was
/// it accepted, what did it do to the book.
struct Arm<'a> {
    cfg: &'a SimConfig,
    market: &'a dyn PricePath,
    requests: &'a [Request],
    disclosure: &'a mut Disclosure,
    options: &'a ArmOptions,
    leakage: Box<dyn LeakagePolicy>,
    rng: PyRandom,
    mms: Vec<MarketMaker>,
    beliefs: Vec<BeliefState>,
    by_step: BTreeMap<usize, Vec<usize>>,
    retries: BTreeMap<usize, u32>,
    probes_by_step: BTreeMap<usize, Vec<Probe>>,
    out: ArmResult,
    quoting_samples: u64,
    quoting_active: u64,
    last_release: Option<Release>,
    window: WindowState,
}

impl<'a> Arm<'a> {
    fn new(
        cfg: &'a SimConfig,
        market: &'a dyn PricePath,
        requests: &'a [Request],
        makers: &[MarketMaker],
        disclosure: &'a mut Disclosure,
        options: &'a ArmOptions,
    ) -> Self {
        // Requests are indices into the shared stream, so a retry is scheduled
        // without copying and every arm still replays exactly one stream.
        let mut by_step: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (index, request) in requests.iter().enumerate() {
            by_step.entry(request.step).or_default().push(index);
        }
        let mut probes_by_step: BTreeMap<usize, Vec<Probe>> = BTreeMap::new();
        for probe in &options.probes {
            probes_by_step.entry(probe.step).or_default().push(*probe);
        }
        let name = disclosure.name();
        Arm {
            leakage: leakage_policy(&options.protocol),
            rng: PyRandom::new(options.seed),
            mms: makers.to_vec(),
            beliefs: vec![BeliefState::default(); makers.len()],
            by_step,
            retries: BTreeMap::new(),
            probes_by_step,
            out: ArmResult {
                protocol: options.protocol.clone(),
                disclosure: name,
                requests: requests.len(),
                fills: 0,
                no_quote: 0,
                rejected: 0,
                user_cost_ticks: Vec::new(),
                mm_pnl: BTreeMap::new(),
                mm_markouts: MARKOUT_HORIZONS
                    .iter()
                    .map(|(k, _)| (*k, Vec::new()))
                    .collect(),
                quote_continuation: 0.0,
                releases: Vec::new(),
                release_errors: [("requests", Vec::new()), ("signed_volume", Vec::new())]
                    .into_iter()
                    .collect(),
                suppression_rate: 0.0,
                observations: Vec::new(),
                settlements: Vec::new(),
                truth: Vec::new(),
                windows: Vec::new(),
                epsilon_spent_max: 0.0,
                probe_results: Vec::new(),
            },
            quoting_samples: 0,
            quoting_active: 0,
            last_release: None,
            window: WindowState::default(),
            cfg,
            market,
            requests,
            disclosure,
            options,
        }
    }

    /// What the venue currently believes about informed flow.
    fn public(&self) -> PublicSignal {
        match &self.last_release {
            Some(release) => self.disclosure.public_signal(release),
            None => (None, f64::INFINITY),
        }
    }

    /// What one maker receives.  A selective release and a venue-wide release
    /// are different experiments because the latter lets every maker narrow at
    /// once and compete away the information surplus.
    fn public_for(&self, mm_id: usize) -> PublicSignal {
        public_for(self.disclosure, self.last_release.as_ref(), mm_id)
    }

    fn record(&mut self, req: &Request, step: usize, executed: bool) {
        self.out.truth.push(Truth {
            step,
            entity: req.entity,
            wallet: req.wallet,
            size: req.size,
            direction: req.direction,
            executed,
            informed: req.informed,
        });
    }

    /// The cheapest eligible maker, in the user's own units.
    ///
    /// Cost rather than price, so one comparison serves both directions: a buyer
    /// minimises the ask and a seller maximises the bid, which is minimising its
    /// negation.
    fn best_quote(&self, req: &Request, ref_mid: i64) -> Option<(i64, usize)> {
        let mut best: Option<(i64, usize)> = None;
        for mm in self.mms.iter().filter(|m| m.eligible(req.size)) {
            let phi_hat = self.beliefs[mm.mm_id].combined(self.public_for(mm.mm_id));
            let (ask, bid) = mm.quote(ref_mid, req.size, phi_hat);
            let price = if req.direction == 0 { ask } else { bid };
            let cost = if req.direction == 0 { price } else { -price };
            if best.is_none_or(|(c, _)| cost < c) {
                best = Some((cost, mm.mm_id));
            }
        }
        best.map(|(cost, id)| (if req.direction == 0 { cost } else { -cost }, id))
    }

    /// The user's walk-away rule.
    ///
    /// An informed user pays up to the move it expects; an uninformed one prices
    /// off whatever the venue published, which is the only channel through which
    /// disclosure can change the flow. The limit stays fractional, because the
    /// estimate is a float and rounding it moves the boundary by half a tick.
    fn accepts(&self, req: &Request, quote: i64, ref_mid: i64) -> bool {
        let limit: f64 = if req.informed {
            let edge = req.signal.abs();
            (if req.direction == 0 {
                ref_mid + edge
            } else {
                ref_mid - edge
            }) as f64
        } else {
            let half = user_half_estimate(self.disclosure.name(), self.last_release.as_ref()).0;
            if req.direction == 0 {
                ref_mid as f64 + half + USER_SLACK_TICKS as f64
            } else {
                ref_mid as f64 - half - USER_SLACK_TICKS as f64
            }
        };
        if req.direction == 0 {
            (quote as f64) <= limit
        } else {
            (quote as f64) >= limit
        }
    }

    /// A real desk does not abandon the trade; it comes back.
    fn retry_later(&mut self, index: usize, step: usize) {
        let attempts = self.retries.get(&index).copied().unwrap_or(0);
        let later = step + self.options.retry_delay;
        if attempts < self.options.max_retries && later < self.cfg.steps {
            self.retries.insert(index, attempts + 1);
            self.by_step.entry(later).or_default().push(index);
        }
    }

    fn execute(
        &mut self,
        req: &Request,
        quote: i64,
        ref_mid: i64,
        mm_id: usize,
        step: usize,
        bucket: usize,
    ) {
        self.out.fills += 1;
        let signed = if req.direction == 0 {
            req.size
        } else {
            -req.size
        };
        self.window.saw_fill(req, bucket, signed);
        let cost_ticks = if req.direction == 0 {
            quote - ref_mid
        } else {
            ref_mid - quote
        };
        self.out.user_cost_ticks.push(cost_ticks as f64);

        self.mms[mm_id].inventory -= signed;
        self.mms[mm_id].fills += 1;
        for (name, horizon) in MARKOUT_HORIZONS {
            let future = self.market.mid()[(step + horizon).min(self.cfg.steps)];
            let pnl = if req.direction == 0 {
                (quote - future) * req.size
            } else {
                (future - quote) * req.size
            };
            self.out
                .mm_markouts
                .get_mut(name)
                .unwrap()
                .push(pnl as f64 / req.size as f64);
            if name == "markout_1s" {
                self.mms[mm_id].realized_pnl += pnl as f64;
                self.beliefs[mm_id].observe_fill(pnl < 0);
            }
        }
        if self.mms[mm_id].inventory.abs() >= self.mms[mm_id].inv_limit {
            self.mms[mm_id].quoting = false;
        }
        self.out.settlements.push(Settlement {
            step,
            wallet: req.wallet,
            entity: req.entity,
            size: req.size,
            direction: req.direction,
            price: quote,
            mm_id,
        });
    }

    fn handle(&mut self, index: usize, step: usize, ref_mid: i64) {
        let req = self.requests[index];
        let bucket = size_bucket(req.size);
        self.window.saw_request(&req, bucket);
        let mut seen = self.leakage.observe(step, &req);

        let Some((quote, mm_id)) = self.best_quote(&req, ref_mid) else {
            self.out.no_quote += 1;
            self.window.saw_no_quote();
            self.record(&req, step, false);
            if let Some(s) = seen {
                self.out.observations.push(s);
            }
            return;
        };

        if !self.accepts(&req, quote, ref_mid) {
            self.out.rejected += 1;
            self.record(&req, step, false);
            if let Some(s) = seen {
                self.out.observations.push(s);
            }
            if self.options.reactive {
                self.retry_later(index, step);
            }
            return;
        }

        self.execute(&req, quote, ref_mid, mm_id, step, bucket);
        self.record(&req, step, true);
        if let Some(s) = seen.as_mut() {
            s.executed = true;
            self.out.observations.push(*s);
        }
    }

    /// A firm price comes back in every arm by design, which is why probing
    /// survives obliviousness.
    fn answer_probe(&mut self, probe: Probe, step: usize, ref_mid: i64) {
        let (mut best_ask, mut best_bid): (Option<i64>, Option<i64>) = (None, None);
        let mut per_mm = BTreeMap::new();
        for mm in self.mms.iter().filter(|m| m.eligible(probe.size)) {
            let phi_hat = self.beliefs[mm.mm_id].combined(self.public_for(mm.mm_id));
            let (ask, bid) = mm.quote(ref_mid, probe.size, phi_hat);
            per_mm.insert(mm.mm_id, (ask, bid));
            if best_ask.is_none_or(|a| ask < a) {
                best_ask = Some(ask);
            }
            if best_bid.is_none_or(|b| bid > b) {
                best_bid = Some(bid);
            }
        }
        self.out.probe_results.push(ProbeResult {
            step,
            size: probe.size,
            best_ask,
            best_bid,
            per_mm_quotes: self.leakage.leaks_per_maker_quotes().then_some(per_mm),
            per_mm_inventory: self.mms.iter().map(|m| (m.mm_id, m.inventory)).collect(),
            true_net_inventory: self.mms.iter().map(|m| m.inventory).sum(),
            ref_mid,
        });
    }

    fn adapt_spreads(&mut self) {
        for mm in self.mms.iter_mut() {
            let realized = mm.realized_pnl / (mm.fills.max(1) as f64);
            if realized < 0.0 {
                mm.base_half = (mm.base_half + 1).min(60);
            } else if realized > 400.0 && mm.base_half > 4 {
                mm.base_half -= 1;
            }
        }
    }

    fn unwind(&mut self) {
        for mm in self.mms.iter_mut() {
            if mm.inventory != 0 {
                mm.inventory -= mm.inventory.abs().min(3) * mm.inventory.signum();
            }
            if !mm.quoting && (mm.inventory.abs() as f64) < mm.inv_limit as f64 * 0.6 {
                mm.quoting = true;
            }
        }
    }

    fn close_window(&mut self, step: usize) {
        // Per maker, not venue-wide. A release that reaches one maker and not
        // another has to be counted that way here too; this used to hand the
        // venue-wide signal to every maker, so the published band count was
        // computed as though everyone had received a disclosure that by
        // construction only one of them got. The quote path already went
        // through `public_for`; this was the one place that did not.
        let reached: Vec<PublicSignal> = (0..self.mms.len())
            .map(|mm_id| public_for(&*self.disclosure, self.last_release.as_ref(), mm_id))
            .collect();
        let (makers_in_band, lots_in_band) =
            depth_snapshot(&self.mms, &self.beliefs, self.market.mid()[step], &reached);
        let obs = self.window.observation(
            step / self.cfg.window_steps,
            step,
            makers_in_band,
            lots_in_band,
        );
        let release = self.disclosure.release(&obs, &mut self.rng);
        if release.published && release.mode == "C_dp" {
            self.out
                .release_errors
                .get_mut("requests")
                .unwrap()
                .push((release.fields.noisy_requests - release.fields.exact_requests).abs() as f64);
            self.out
                .release_errors
                .get_mut("signed_volume")
                .unwrap()
                .push(
                    (release.fields.noisy_signed_volume - release.fields.exact_signed_volume).abs()
                        as f64,
                );
        }
        self.out.windows.push(obs);
        self.last_release = Some(release.clone());
        self.out.releases.push(release);
        self.window = WindowState {
            start: step + 1,
            ..Default::default()
        };
    }

    /// The loop itself, now short enough to read.
    fn run(mut self) -> ArmResult {
        for step in 0..self.cfg.steps {
            let ref_mid = self.market.mid()[step];
            for index in self.by_step.get(&step).cloned().unwrap_or_default() {
                self.handle(index, step, ref_mid);
            }
            for probe in self.probes_by_step.get(&step).cloned().unwrap_or_default() {
                self.answer_probe(probe, step, ref_mid);
            }
            if self.options.reactive && step % 400 == 399 {
                self.adapt_spreads();
            }
            self.unwind();
            self.quoting_samples += self.mms.len() as u64;
            self.quoting_active += self.mms.iter().filter(|m| m.quoting).count() as u64;
            if (step + 1) % self.cfg.window_steps == 0 {
                self.close_window(step);
            }
        }
        self.finish()
    }

    fn finish(mut self) -> ArmResult {
        self.out.quote_continuation = if self.quoting_samples == 0 {
            0.0
        } else {
            self.quoting_active as f64 / self.quoting_samples as f64
        };
        self.out.suppression_rate = if self.out.releases.is_empty() {
            0.0
        } else {
            self.out.releases.iter().filter(|r| !r.published).count() as f64
                / self.out.releases.len() as f64
        };
        self.out.mm_pnl = self.mms.iter().map(|m| (m.mm_id, m.realized_pnl)).collect();
        self.out.epsilon_spent_max = self.disclosure.epsilon_spent_max();
        self.out
    }
}

/// Run one arm. The work is in `Arm`; this is the name callers know.
pub fn run_arm(
    cfg: &SimConfig,
    market: &dyn PricePath,
    requests: &[Request],
    makers: &[MarketMaker],
    disclosure: &mut Disclosure,
    options: &ArmOptions,
) -> ArmResult {
    Arm::new(cfg, market, requests, makers, disclosure, options).run()
}

fn depth_snapshot(
    mms: &[MarketMaker],
    beliefs: &[BeliefState],
    ref_mid: i64,
    reached: &[PublicSignal],
) -> (i64, i64) {
    const BAND_BPS: i64 = 5;
    const PROBE_SIZE: i64 = 100;
    let band = BAND_BPS * ref_mid / 10_000;
    let (mut count, mut lots) = (0i64, 0i64);
    for mm in mms.iter().filter(|m| m.eligible(PROBE_SIZE)) {
        let phi_hat = beliefs[mm.mm_id].combined(reached[mm.mm_id]);
        let (ask, bid) = mm.quote(ref_mid, PROBE_SIZE, phi_hat);
        if (ask - ref_mid).abs() <= band && (bid - ref_mid).abs() <= band {
            count += 1;
            lots += mm.max_qty;
        }
    }
    (count, lots)
}
