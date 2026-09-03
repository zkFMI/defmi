//! Running every arm against one market, and collecting what each attacker got.
//!
//! An arm is a protocol crossed with a disclosure regime. The matrix is the
//! comparison the study is built on: varying the two independently is what lets
//! an effect be attributed to one of them rather than to the pair.

use crate::attackers::{self as atk, AttackReport};
use crate::disclosure::{Disclosure, DpDisclosure};
use crate::engine::{run_arm, ArmOptions, ArmResult, Probe};
use crate::market::{build_market_makers, build_requests, ReferenceMarket, SimConfig};
use crate::tapes::{requests_from_tape, Entities, Tape, TapeMarket};

#[derive(Clone, Copy, Debug)]
pub struct DpParams {
    pub epsilon_per_window: f64,
    pub epsilon_total: f64,
    pub request_cap: i64,
    pub volume_cap: i64,
    /// Correcting the absolute-value skew is the default now that its cause is
    /// known; the uncorrected arm stays reachable so the negative result can be
    /// reproduced against its own fix rather than against nothing.
    pub debias: bool,
    pub signed_sensitivity_factor: f64,
}

impl Default for DpParams {
    fn default() -> Self {
        DpParams {
            epsilon_per_window: 1.0,
            epsilon_total: 20.0,
            request_cap: 3,
            volume_cap: 300,
            debias: true,
            signed_sensitivity_factor: 1.0,
        }
    }
}

pub fn make_disclosure(name: &str, cfg: &SimConfig, dp: &DpParams) -> Disclosure {
    match name {
        "A_none" => Disclosure::None,
        "B_threshold" => Disclosure::Threshold {
            min_makers: 5,
            min_lots: 800,
        },
        "C_dp" => {
            let mut mechanism = DpDisclosure::new(
                dp.epsilon_per_window,
                dp.request_cap,
                dp.volume_cap,
                cfg.n_entities,
                dp.epsilon_total,
                dp.debias,
            );
            mechanism.signed_sensitivity_factor = dp.signed_sensitivity_factor;
            Disclosure::Dp(Box::new(mechanism))
        }
        other => panic!("no such disclosure regime: {other}"),
    }
}

/// A probing entity spends its whole allowance, evenly spread. A prefix would
/// confound the budget with the period observed.
pub fn build_probes(cfg: &SimConfig, per_window: usize, probe_size: i64) -> Vec<Probe> {
    let n_windows = cfg.steps / cfg.window_steps;
    let attacker_entity = cfg.n_entities; // outside the honest population
    let mut probes = Vec::with_capacity(n_windows * per_window);
    for window in 0..n_windows {
        for k in 0..per_window {
            let offset = ((k as f64 + 0.5) * cfg.window_steps as f64 / per_window as f64) as usize;
            probes.push(Probe {
                step: (window * cfg.window_steps + offset).min(cfg.steps - 1),
                size: probe_size,
                wallet: 10_000 + k,
                entity: attacker_entity,
            });
        }
    }
    probes
}

pub struct ArmRow {
    pub protocol: String,
    pub disclosure: String,
    pub layer: String,
    pub result: ArmResult,
    pub attacks: Vec<AttackReport>,
    pub tape_meta: Option<std::collections::BTreeMap<String, f64>>,
}

/// Which behavioural layer an arm runs in.
///
/// `Replay` gives every arm the identical request stream, which isolates the
/// protocol. `Reactive` lets rejected flow come back and makers adapt, so the
/// arm reshapes its own flow --- closer to a desk, and the only layer in which a
/// disclosure regime can help or hurt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Replay,
    Reactive,
}

impl Layer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Layer::Replay => "replay",
            Layer::Reactive => "reactive",
        }
    }
}

pub fn run_matrix(
    cfg: &SimConfig,
    dp: &DpParams,
    protocols: &[&str],
    disclosures: &[&str],
    layer: Layer,
    probe_per_window: usize,
) -> Vec<ArmRow> {
    let market = ReferenceMarket::new(cfg, cfg.seed);
    let makers = build_market_makers(cfg, cfg.seed + 1);
    let probes = build_probes(cfg, probe_per_window, 50);
    let mut rows = Vec::new();

    for protocol in protocols {
        for name in disclosures {
            let requests = build_requests(cfg, &market, cfg.seed + 2);
            let mut disclosure = make_disclosure(name, cfg, dp);
            let mut options = ArmOptions::new(protocol, cfg.seed + 5);
            options.probes = probes.clone();
            options.reactive = layer == Layer::Reactive;
            let result = run_arm(cfg, &market, &requests, &makers, &mut disclosure, &options);
            let attacks = vec![
                atk::passive_observer(&result, cfg, 0.5, cfg.seed),
                atk::pretrade_attributes(&result, cfg),
                atk::window_shift_observer(&result, cfg),
                atk::probing_entity(&result, probes.len()),
                atk::colluding_wallets(&result, cfg, 4, 4),
                atk::external_info_observer(&result, cfg, &market),
            ];
            rows.push(ArmRow {
                protocol: protocol.to_string(),
                disclosure: name.to_string(),
                layer: layer.as_str().to_string(),
                result,
                attacks,
                tape_meta: None,
            });
        }
    }
    rows
}

/// Run the same experiment matrix against one observed tape rather than a
/// generated order stream.
#[derive(Clone, Copy, Debug)]
pub struct TapeMatrixOptions {
    pub layer: Layer,
    pub probes_per_window: usize,
    pub entities: Entities,
    pub wallets_per_entity: usize,
}

pub fn run_matrix_with_tape(
    cfg: &SimConfig,
    dp: &DpParams,
    protocols: &[&str],
    disclosures: &[&str],
    tape: &Tape,
    matrix_options: TapeMatrixOptions,
) -> Vec<ArmRow> {
    let market = TapeMarket::new(cfg, tape, 20, 60.0, 200, cfg.seed);
    let loaded = requests_from_tape(
        cfg,
        &market,
        tape,
        matrix_options.entities,
        matrix_options.wallets_per_entity,
        cfg.seed + 2,
    );
    let cfg = loaded.cfg;
    let makers = build_market_makers(&cfg, cfg.seed + 1);
    let probes = build_probes(&cfg, matrix_options.probes_per_window, 50);
    let mut rows = Vec::new();
    for protocol in protocols {
        for name in disclosures {
            let mut disclosure = make_disclosure(name, &cfg, dp);
            let mut arm_options = ArmOptions::new(protocol, cfg.seed + 5);
            arm_options.probes = probes.clone();
            arm_options.reactive = matrix_options.layer == Layer::Reactive;
            let result = run_arm(
                &cfg,
                &market,
                &loaded.requests,
                &makers,
                &mut disclosure,
                &arm_options,
            );
            let attacks = vec![
                atk::passive_observer(&result, &cfg, 0.5, cfg.seed),
                atk::pretrade_attributes(&result, &cfg),
                atk::window_shift_observer(&result, &cfg),
                atk::probing_entity(&result, probes.len()),
                atk::colluding_wallets(&result, &cfg, 4, 4),
                atk::external_info_observer(&result, &cfg, &market),
            ];
            rows.push(ArmRow {
                protocol: (*protocol).to_string(),
                disclosure: (*name).to_string(),
                layer: matrix_options.layer.as_str().to_string(),
                result,
                attacks,
                tape_meta: Some(loaded.meta.clone()),
            });
        }
    }
    rows
}
