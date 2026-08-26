//! Reference market, order flow and maker behaviour.
//!
//! The pricing rule here is the same function the MPC circuit evaluates,
//!
//! ```text
//! ask_i = mid_i + half_i + slope_i * x + invcoef_i * inv_i
//! bid_i = mid_i - half_i - slope_i * x + invcoef_i * inv_i
//! ```
//!
//! so a simulation result and a circuit result can be checked against each
//! other. All quantities are integers: prices in ticks, sizes in lots.
//!
//! Every draw goes through [`crate::pyrandom`], which reproduces CPython's
//! stream, so this market is the same market the published runs used rather
//! than a market with the same distribution.

use crate::pyrandom::PyRandom;

pub const SIZE_BUCKETS: [(i64, i64); 3] = [(1, 20), (21, 100), (101, 400)];
pub const BUCKET_NAMES: [&str; 3] = ["small", "medium", "large"];

/// Inventory is carried in lots; the skew it induces is in ticks, so the raw
/// inventory is divided by this before the coefficient applies.
pub const INV_SCALE: i64 = 32;

pub fn size_bucket(size: i64) -> usize {
    for (index, (lo, hi)) in SIZE_BUCKETS.iter().enumerate() {
        if size >= *lo && size <= *hi {
            return index;
        }
    }
    SIZE_BUCKETS.len() - 1
}

pub use qomm_measure::pyround::py_round;


#[derive(Clone, Copy, Debug)]
pub struct SimConfig {
    pub steps: usize,
    pub step_ms: u64,
    pub n_mm: usize,
    pub n_entities: usize,
    pub wallets_per_entity: usize,
    pub ref_mid0: i64,
    pub sigma_ticks: f64,
    /// Requests per step across all entities.
    pub arrival_rate: f64,
    pub informed_base: f64,
    pub informed_ar: f64,
    pub informed_sd: f64,
    /// Expected mid move that informed flow predicts.
    pub informed_edge_ticks: f64,
    pub window_steps: usize,
    pub seed: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        SimConfig {
            steps: 48_000,
            step_ms: 50,
            n_mm: 16,
            n_entities: 24,
            wallets_per_entity: 3,
            ref_mid0: 100_000,
            sigma_ticks: 6.0,
            arrival_rate: 0.15,
            informed_base: 0.30,
            informed_ar: 0.995,
            informed_sd: 0.05,
            informed_edge_ticks: 22.0,
            window_steps: 1_200,
            seed: 20_260_818,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub step: usize,
    pub entity: usize,
    pub wallet: usize,
    pub size: i64,
    /// 0 = the user buys, 1 = the user sells.
    pub direction: u8,
    pub informed: bool,
    /// The informed trader's view of the coming mid move.
    pub signal: i64,
}

#[derive(Clone, Debug)]
pub struct MarketMaker {
    pub mm_id: usize,
    pub base_half: i64,
    pub slope: i64,
    pub inv_coef: i64,
    pub max_qty: i64,
    /// Adverse-selection loading on the half spread.
    pub kappa: f64,
    pub inv_limit: i64,
    pub inventory: i64,
    pub fills: u64,
    pub realized_pnl: f64,
    pub quoting: bool,
    /// A conditional on a secret, which the rule language allows through min and
    /// max. Optional because whether it earns its six rounds is a measurement.
    pub skew_cap: Option<i64>,
}

impl MarketMaker {
    /// Half spread = fixed cost + adverse-selection premium.
    ///
    /// The premium is proportional to the maker's *estimate* of the informed
    /// fraction, which is the channel through which public market information
    /// could improve maker profitability --- and the channel the disclosure
    /// results are about.
    pub fn half_spread(&self, phi_hat: f64, size: i64) -> i64 {
        let premium = self.kappa * phi_hat.max(0.0) * (size.max(1) as f64).sqrt();
        self.base_half + py_round(premium)
    }

    pub fn quote(&self, ref_mid: i64, size: i64, phi_hat: f64) -> (i64, i64) {
        let half = self.half_spread(phi_hat, size);
        let depth = self.slope * size;
        let mut skew = self.inv_coef * self.inventory.div_euclid(INV_SCALE);
        if let Some(cap) = self.skew_cap {
            skew = skew.clamp(-cap, cap);
        }
        (ref_mid + half + depth + skew, ref_mid - half - depth + skew)
    }

    pub fn eligible(&self, size: i64) -> bool {
        self.quoting && size <= self.max_qty && self.inventory.abs() < self.inv_limit
    }
}

/// Public reference mid plus a latent informed-flow intensity.
pub struct ReferenceMarket {
    pub mid: Vec<i64>,
    pub phi: Vec<f64>,
}

/// The simulation and its external-information attacker need only a public
/// reference-price path. Generated and observed tape markets both provide it.
pub trait PricePath {
    fn mid(&self) -> &[i64];
}

impl PricePath for ReferenceMarket {
    fn mid(&self) -> &[i64] {
        &self.mid
    }
}

impl ReferenceMarket {
    pub fn new(cfg: &SimConfig, seed: u64) -> Self {
        let mut rng = PyRandom::new(seed);
        let mut mid_values = vec![cfg.ref_mid0];
        let mut phi_values = vec![cfg.informed_base];
        let mut phi = cfg.informed_base;
        let mut mid = cfg.ref_mid0 as f64;
        for _ in 0..cfg.steps {
            mid += rng.gauss(0.0, cfg.sigma_ticks);
            mid_values.push(py_round(mid));
            phi = cfg.informed_base
                + cfg.informed_ar * (phi - cfg.informed_base)
                + rng.gauss(0.0, cfg.informed_sd);
            phi = phi.clamp(0.02, 0.95);
            phi_values.push(phi);
        }
        ReferenceMarket {
            mid: mid_values,
            phi: phi_values,
        }
    }

    pub fn move_over(&self, step: usize, horizon: usize) -> i64 {
        let end = (step + horizon).min(self.mid.len() - 1);
        self.mid[end] - self.mid[step]
    }
}

pub fn build_market_makers(cfg: &SimConfig, seed: u64) -> Vec<MarketMaker> {
    let mut rng = PyRandom::new(seed);
    (0..cfg.n_mm)
        .map(|i| MarketMaker {
            mm_id: i,
            base_half: rng.randint(6, 18),
            slope: *rng.choice(&[0i64, 0, 1, 1, 2]),
            inv_coef: *rng.choice(&[0i64, 1, 1, 2]),
            max_qty: *rng.choice(&[100i64, 200, 400, 400]),
            kappa: rng.uniform(1.5, 4.0),
            inv_limit: *rng.choice(&[600i64, 900, 1200]),
            inventory: 0,
            fills: 0,
            realized_pnl: 0.0,
            quoting: true,
            skew_cap: None,
        })
        .collect()
}

/// One shared request stream. Every arm replays exactly this stream, which is
/// what makes the arms comparable at all.
pub fn build_requests(cfg: &SimConfig, market: &ReferenceMarket, seed: u64) -> Vec<Request> {
    let mut rng = PyRandom::new(seed);
    let mut requests = Vec::new();

    // Entity activity is heterogeneous: a few large entities dominate, which is
    // what a real venue looks like and what makes a per-entity cap bite.
    let raw: Vec<f64> = (0..cfg.n_entities)
        .map(|_| rng.paretovariate(1.6))
        .collect();
    let total: f64 = raw.iter().sum();
    let weights: Vec<f64> = raw.iter().map(|w| w / total).collect();

    for step in 0..cfg.steps {
        if rng.random() >= cfg.arrival_rate {
            continue;
        }
        let entity = weighted_choice(&mut rng, &weights);
        let wallet = entity * cfg.wallets_per_entity
            + rng.randrange(0, cfg.wallets_per_entity as i64) as usize;
        let bucket = rng.choices(&[0.55, 0.33, 0.12]);
        let (lo, hi) = SIZE_BUCKETS[bucket];
        let size = rng.randint(lo, hi);
        let informed = rng.random() < market.phi[step];
        let (direction, signal) = if informed {
            let future = market.move_over(step, 20);
            // informed flow buys ahead of a rise
            (u8::from(future <= 0), future)
        } else {
            (rng.randrange(0, 2) as u8, 0)
        };
        requests.push(Request {
            step,
            entity,
            wallet,
            size,
            direction,
            informed,
            signal,
        });
    }
    requests
}

fn weighted_choice(rng: &mut PyRandom, weights: &[f64]) -> usize {
    let draw = rng.random();
    let mut acc = 0.0;
    for (index, w) in weights.iter().enumerate() {
        acc += w;
        if draw <= acc {
            return index;
        }
    }
    weights.len() - 1
}
