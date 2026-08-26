//! A small bench for turning one simulation knob at a time.
//!
//! This module assembles the same market, makers, requests, probes and
//! disclosure mechanisms as [`crate::experiment`]. A setup owns one market and
//! request stream and every compared arm reuses them, so protocol comparisons
//! cannot accidentally compare different markets.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::attackers;
use crate::engine::{run_arm, ArmOptions, ArmResult, Probe};
use crate::experiment::{build_probes, make_disclosure, DpParams};
use crate::market::{
    build_market_makers, build_requests, MarketMaker, PricePath, ReferenceMarket, Request,
    SimConfig,
};
use crate::tapes::{load_bybit, load_uniswapx, requests_from_tape, Entities, TapeMarket};

pub const PROTOCOLS: [&str; 6] = [
    "plain_rfq",
    "plain_rfm",
    "plain_rfs",
    "qomm_rfq",
    "qomm_rfm",
    "qomm_rfs",
];
pub const DISCLOSURES: [&str; 3] = ["A_none", "B_threshold", "C_dp"];

pub enum LabMarket {
    Generated(ReferenceMarket),
    Tape(TapeMarket),
}

impl PricePath for LabMarket {
    fn mid(&self) -> &[i64] {
        match self {
            LabMarket::Generated(market) => market.mid(),
            LabMarket::Tape(market) => market.mid(),
        }
    }
}

pub struct Setup {
    pub cfg: SimConfig,
    pub market: LabMarket,
    pub makers: Vec<MarketMaker>,
    pub requests: Vec<Request>,
    pub probes: Vec<Probe>,
    pub source: String,
    pub meta: BTreeMap<String, f64>,
}

impl Setup {
    pub fn describe(&self) -> String {
        let seconds = self.cfg.steps as f64 * self.cfg.step_ms as f64 / 1_000.0;
        let rate = self.requests.len() as f64 / seconds.max(1.0);
        format!(
            "{}: {} requests over {} steps ({rate:.2}/s), {} entities, {} makers",
            self.source,
            self.requests.len(),
            self.cfg.steps,
            self.cfg.n_entities,
            self.cfg.n_mm
        )
    }
}

#[derive(Clone, Debug)]
pub struct BuildOptions {
    pub cfg: SimConfig,
    pub tape: Option<PathBuf>,
    pub tape_kind: String,
    pub tape_step_ms: u64,
    pub tape_step_blocks: usize,
    pub tape_entities: Option<usize>,
    pub probes_per_window: usize,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            cfg: SimConfig::default(),
            tape: None,
            tape_kind: "bybit".to_string(),
            tape_step_ms: 1_000,
            tape_step_blocks: 150,
            // One entity per observed address, not a round-robin collapse into a
            // fixed count. Collapsing 600 observed addresses into 24 synthetic
            // entities is the least skewed assignment available, so a per-entity
            // cap binds 24 synthetic entities rather than the 600 real ones, and
            // the real distribution -- 48,000 swappers of whom 59.6% appear once
            // -- is flattened away. It is the same collapse that made the
            // block-range query saturate in one window on generated data. The
            // conservative default is the setting least favourable to the venue.
            tape_entities: None,
            probes_per_window: 6,
        }
    }
}

pub fn build(options: &BuildOptions) -> Result<Setup, String> {
    let (cfg, market, requests, source, meta) = match &options.tape {
        None => {
            let cfg = options.cfg;
            let market = ReferenceMarket::new(&cfg, cfg.seed);
            let requests = build_requests(&cfg, &market, cfg.seed + 2);
            (
                cfg,
                LabMarket::Generated(market),
                requests,
                "generated".to_string(),
                BTreeMap::new(),
            )
        }
        Some(path) if options.tape_kind == "bybit" => {
            let text = fs::read_to_string(path)
                .map_err(|error| format!("reading {}: {error}", path.display()))?;
            let tape = load_bybit(
                &text,
                &options.cfg,
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("tape.csv"),
                Some(options.cfg.steps),
                Some(options.tape_step_ms),
                None,
            )?;
            let tape_market = TapeMarket::new(&options.cfg, &tape, 20, 60.0, 200, options.cfg.seed);
            let entities = options
                .tape_entities
                .map_or(Entities::PerAddress, Entities::RoundRobin);
            let loaded = requests_from_tape(
                &options.cfg,
                &tape_market,
                &tape,
                entities,
                1,
                options.cfg.seed + 2,
            );
            (
                loaded.cfg,
                LabMarket::Tape(tape_market),
                loaded.requests,
                tape.source,
                loaded.meta,
            )
        }
        Some(path) if options.tape_kind == "uniswapx" => {
            let text = fs::read_to_string(path)
                .map_err(|error| format!("reading {}: {error}", path.display()))?;
            let tape = load_uniswapx(
                &text,
                &options.cfg,
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("tape.jsonl"),
                Some(options.cfg.steps),
                options.tape_step_blocks,
                1,
                None,
            )?;
            let tape_market = TapeMarket::new(&options.cfg, &tape, 20, 60.0, 200, options.cfg.seed);
            let entities = options
                .tape_entities
                .map_or(Entities::PerAddress, Entities::RoundRobin);
            let loaded = requests_from_tape(
                &options.cfg,
                &tape_market,
                &tape,
                entities,
                1,
                options.cfg.seed + 2,
            );
            (
                loaded.cfg,
                LabMarket::Tape(tape_market),
                loaded.requests,
                tape.source,
                loaded.meta,
            )
        }
        Some(_) => {
            return Err(format!(
                "unsupported tape kind '{}'; use bybit or uniswapx",
                options.tape_kind
            ))
        }
    };
    let makers = build_market_makers(&cfg, cfg.seed + 1);
    let probes = build_probes(&cfg, options.probes_per_window, 50);
    Ok(Setup {
        cfg,
        market,
        makers,
        requests,
        probes,
        source,
        meta,
    })
}

#[derive(Clone, Debug)]
pub struct ArmParams {
    pub protocol: String,
    pub disclosure: String,
    pub epsilon: f64,
    pub reactive: bool,
    pub rho: f64,
    pub debias: bool,
    pub signed_sensitivity_factor: f64,
}

impl Default for ArmParams {
    fn default() -> Self {
        Self {
            protocol: "plain_rfq".to_string(),
            disclosure: "A_none".to_string(),
            epsilon: 1.0,
            reactive: false,
            rho: 0.5,
            debias: true,
            signed_sensitivity_factor: 1.0,
        }
    }
}

pub struct ArmRow {
    pub protocol: String,
    pub disclosure: String,
    pub epsilon: f64,
    pub rho: f64,
    pub reactive: bool,
    pub fill_rate: f64,
    pub mm_pnl_per_fill: Option<f64>,
    pub suppression_rate: Option<f64>,
    pub detection_auc: Option<f64>,
    pub detection_cells: usize,
    pub entities_covered: Option<f64>,
    pub informed_auc: Option<f64>,
    pub result: ArmResult,
}

pub fn arm(setup: &Setup, params: &ArmParams) -> ArmRow {
    let dp = DpParams {
        epsilon_per_window: params.epsilon,
        debias: params.debias,
        signed_sensitivity_factor: params.signed_sensitivity_factor,
        ..DpParams::default()
    };
    let mut disclosure = make_disclosure(&params.disclosure, &setup.cfg, &dp);
    let mut options = ArmOptions::new(&params.protocol, setup.cfg.seed + 5);
    options.probes = setup.probes.clone();
    options.reactive = params.reactive;
    let result = run_arm(
        &setup.cfg,
        &setup.market,
        &setup.requests,
        &setup.makers,
        &mut disclosure,
        &options,
    );
    let passive = attackers::passive_observer(&result, &setup.cfg, params.rho, setup.cfg.seed);
    let informed = attackers::external_info_observer(&result, &setup.cfg, &setup.market);
    ArmRow {
        protocol: params.protocol.clone(),
        disclosure: params.disclosure.clone(),
        epsilon: params.epsilon,
        rho: params.rho,
        reactive: params.reactive,
        fill_rate: result.fill_rate(),
        mm_pnl_per_fill: result.mm_pnl_per_fill(),
        suppression_rate: (params.disclosure != "A_none").then_some(result.suppression_rate),
        detection_auc: passive.auc,
        detection_cells: passive.n_examples,
        entities_covered: passive.extra.get("entities_covered").copied().flatten(),
        informed_auc: informed.auc,
        result,
    }
}

pub fn sweep_rho(setup: &Setup, values: &[f64], fixed: &ArmParams) -> Vec<ArmRow> {
    values
        .iter()
        .map(|value| {
            let mut params = fixed.clone();
            params.rho = *value;
            arm(setup, &params)
        })
        .collect()
}

pub fn sweep_epsilon(setup: &Setup, values: &[f64], fixed: &ArmParams) -> Vec<ArmRow> {
    values
        .iter()
        .map(|value| {
            let mut params = fixed.clone();
            params.epsilon = *value;
            arm(setup, &params)
        })
        .collect()
}

/// Typed equivalent of Python's dynamic `sweep(setup, over, values, **fixed)`.
pub enum Sweep<'a> {
    Rho(&'a [f64]),
    Epsilon(&'a [f64]),
    Protocol(&'a [&'a str]),
    Disclosure(&'a [&'a str]),
    Reactive(&'a [bool]),
    Debias(&'a [bool]),
    SignedSensitivity(&'a [f64]),
}

pub fn sweep(setup: &Setup, over: Sweep<'_>, fixed: &ArmParams) -> Vec<ArmRow> {
    match over {
        Sweep::Rho(values) => sweep_rho(setup, values, fixed),
        Sweep::Epsilon(values) => sweep_epsilon(setup, values, fixed),
        Sweep::Protocol(values) => values
            .iter()
            .map(|value| {
                let mut params = fixed.clone();
                params.protocol = (*value).to_string();
                arm(setup, &params)
            })
            .collect(),
        Sweep::Disclosure(values) => values
            .iter()
            .map(|value| {
                let mut params = fixed.clone();
                params.disclosure = (*value).to_string();
                arm(setup, &params)
            })
            .collect(),
        Sweep::Reactive(values) => values
            .iter()
            .map(|value| {
                let mut params = fixed.clone();
                params.reactive = *value;
                arm(setup, &params)
            })
            .collect(),
        Sweep::Debias(values) => values
            .iter()
            .map(|value| {
                let mut params = fixed.clone();
                params.debias = *value;
                arm(setup, &params)
            })
            .collect(),
        Sweep::SignedSensitivity(values) => values
            .iter()
            .map(|value| {
                let mut params = fixed.clone();
                params.signed_sensitivity_factor = *value;
                arm(setup, &params)
            })
            .collect(),
    }
}

pub fn compare(setup: &Setup, protocols: &[&str], fixed: &ArmParams) -> Vec<ArmRow> {
    protocols
        .iter()
        .map(|protocol| {
            let mut params = fixed.clone();
            params.protocol = (*protocol).to_string();
            arm(setup, &params)
        })
        .collect()
}

pub fn table(rows: &[ArmRow]) -> String {
    let columns = [
        "protocol",
        "disclosure",
        "rho",
        "detection_auc",
        "fill_rate",
        "mm_pnl_per_fill",
        "suppression_rate",
    ];
    let widths: Vec<usize> = columns.iter().map(|column| column.len().max(11)).collect();
    let mut lines = vec![columns
        .iter()
        .zip(&widths)
        .map(|(value, width)| format!("{value:>width$}"))
        .collect::<Vec<_>>()
        .join("  ")];
    for row in rows {
        let cells = [
            row.protocol.clone(),
            row.disclosure.clone(),
            format!("{:.4}", row.rho),
            row.detection_auc
                .map_or("n/a".to_string(), |value| format!("{value:.4}")),
            format!("{:.4}", row.fill_rate),
            row.mm_pnl_per_fill
                .map_or("n/a".to_string(), |value| format!("{value:.4}")),
            row.suppression_rate
                .map_or("n/a".to_string(), |value| format!("{value:.4}")),
        ];
        lines.push(
            cells
                .iter()
                .zip(&widths)
                .map(|(value, width)| format!("{value:>width$}"))
                .collect::<Vec<_>>()
                .join("  "),
        );
    }
    lines.join("\n")
}

pub fn tapes(root: &Path) -> Result<Vec<PathBuf>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<(PathBuf, u64)> = fs::read_dir(root)
        .map_err(|error| format!("reading {}: {error}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension().and_then(|extension| extension.to_str()) == Some("csv"))
                .then(|| entry.metadata().ok().map(|metadata| (path, metadata.len())))
                .flatten()
        })
        .collect();
    paths.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
    Ok(paths.into_iter().map(|(path, _)| path).collect())
}

pub fn default_tapes() -> Result<Vec<PathBuf>, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("artifacts/tapes");
    tapes(&root)
}
