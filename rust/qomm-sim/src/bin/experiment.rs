//! Command-line equivalent of `qomm_sim.experiment.main`.

use std::fmt::Write as _;
use std::path::PathBuf;

use qomm_sim::attackers::AttackReport;
use qomm_sim::engine::ArmResult;
use qomm_sim::experiment::{run_matrix, ArmRow, DpParams, Layer};
use qomm_sim::market::SimConfig;

fn number(value: Option<f64>) -> String {
    value.map_or_else(|| "null".to_string(), |value| value.to_string())
}

fn mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| qomm_sim::fsum::nsum(values.iter().copied()) / values.len() as f64)
}

fn attack_json(report: &AttackReport) -> String {
    let mut out = format!(
        "{{\"name\":\"{}\",\"target\":\"{}\",\"auc\":{},\"tpr_at_5pct_fpr\":{},\"base_rate\":{},\"advantage\":{},\"n_examples\":{},\"extra\":{{",
        report.name,
        report.target,
        number(report.auc),
        number(report.tpr_at_5pct_fpr),
        report.base_rate,
        number(report.advantage),
        report.n_examples
    );
    for (index, (key, value)) in report.extra.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write!(&mut out, "\"{key}\":{}", number(*value)).unwrap();
    }
    out.push_str("}}");
    out
}

fn result_json(result: &ArmResult) -> String {
    let cost_mean = mean(&result.user_cost_ticks);
    let mut out = format!(
        "{{\"protocol\":\"{}\",\"disclosure\":\"{}\",\"requests\":{},\"fills\":{},\"fill_rate\":{},\"no_quote_rate\":{},\"user_cost_mean_ticks\":{},\"user_cost_median_ticks\":{},\"mm_pnl_total_ticklots\":{},\"mm_pnl_per_fill\":{},\"quote_continuation\":{},\"suppression_rate\":{},\"epsilon_spent_max\":{}",
        result.protocol,
        result.disclosure,
        result.requests,
        result.fills,
        result.fill_rate(),
        if result.requests == 0 { 0.0 } else { result.no_quote as f64 / result.requests as f64 },
        number(cost_mean),
        number(result.user_cost_median()),
        result.mm_pnl_total(),
        number(result.mm_pnl_per_fill()),
        result.quote_continuation,
        result.suppression_rate,
        result.epsilon_spent_max
    );
    for (key, values) in &result.mm_markouts {
        write!(&mut out, ",\"mm_{key}_mean\":{}", number(mean(values))).unwrap();
    }
    for (key, values) in &result.release_errors {
        write!(&mut out, ",\"release_{key}_mae\":{}", number(mean(values))).unwrap();
    }
    out.push('}');
    out
}

fn row_json(row: &ArmRow) -> String {
    let mut summary = result_json(&row.result);
    summary.pop();
    write!(&mut summary, ",\"layer\":\"{}\",\"attacks\":[", row.layer).unwrap();
    for (index, report) in row.attacks.iter().enumerate() {
        if index > 0 {
            summary.push(',');
        }
        summary.push_str(&attack_json(report));
    }
    summary.push_str("]}");
    summary
}

fn take_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn take_list(args: &[String], index: &mut usize, flag: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    while args
        .get(*index + 1)
        .is_some_and(|value| !value.starts_with("--"))
    {
        *index += 1;
        values.push(args[*index].clone());
    }
    if values.is_empty() {
        Err(format!("{flag} needs at least one value"))
    } else {
        Ok(values)
    }
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = SimConfig::default();
    let mut dp = DpParams::default();
    let mut out: Option<PathBuf> = None;
    let mut layers = vec!["replay".to_string(), "reactive".to_string()];
    let mut protocols = qomm_sim::engine::PLAIN_PROTOCOLS
        .into_iter()
        .chain(qomm_sim::engine::QOMM_PROTOCOLS)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut disclosures = vec![
        "A_none".to_string(),
        "B_threshold".to_string(),
        "C_dp".to_string(),
    ];
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        match flag {
            "--out" => out = Some(take_value(&args, &mut index, flag)?.into()),
            "--steps" => {
                cfg.steps = take_value(&args, &mut index, flag)?
                    .parse()
                    .map_err(|_| "bad --steps")?
            }
            "--n-mm" => {
                cfg.n_mm = take_value(&args, &mut index, flag)?
                    .parse()
                    .map_err(|_| "bad --n-mm")?
            }
            "--n-entities" => {
                cfg.n_entities = take_value(&args, &mut index, flag)?
                    .parse()
                    .map_err(|_| "bad --n-entities")?
            }
            "--arrival-rate" => {
                cfg.arrival_rate = take_value(&args, &mut index, flag)?
                    .parse()
                    .map_err(|_| "bad --arrival-rate")?
            }
            "--window-steps" => {
                cfg.window_steps = take_value(&args, &mut index, flag)?
                    .parse()
                    .map_err(|_| "bad --window-steps")?
            }
            "--epsilon-per-window" => {
                dp.epsilon_per_window = take_value(&args, &mut index, flag)?
                    .parse()
                    .map_err(|_| "bad --epsilon-per-window")?
            }
            "--epsilon-total" => {
                dp.epsilon_total = take_value(&args, &mut index, flag)?
                    .parse()
                    .map_err(|_| "bad --epsilon-total")?
            }
            "--seed" => {
                cfg.seed = take_value(&args, &mut index, flag)?
                    .parse()
                    .map_err(|_| "bad --seed")?
            }
            "--layers" => layers = take_list(&args, &mut index, flag)?,
            "--protocols" => protocols = take_list(&args, &mut index, flag)?,
            "--disclosures" => disclosures = take_list(&args, &mut index, flag)?,
            other => return Err(format!("unknown argument: {other}")),
        }
        index += 1;
    }
    let out = out.ok_or("--out is required")?;
    let protocol_refs: Vec<&str> = protocols.iter().map(String::as_str).collect();
    let disclosure_refs: Vec<&str> = disclosures.iter().map(String::as_str).collect();
    let mut rows = Vec::new();
    for layer in layers {
        let layer = match layer.as_str() {
            "replay" => Layer::Replay,
            "reactive" => Layer::Reactive,
            other => return Err(format!("unknown layer: {other}")),
        };
        rows.extend(run_matrix(
            &cfg,
            &dp,
            &protocol_refs,
            &disclosure_refs,
            layer,
            6,
        ));
    }
    let mut payload = format!(
        "{{\"config\":{{\"steps\":{},\"step_ms\":{},\"n_mm\":{},\"n_entities\":{},\"wallets_per_entity\":{},\"ref_mid0\":{},\"sigma_ticks\":{},\"arrival_rate\":{},\"informed_base\":{},\"informed_ar\":{},\"informed_sd\":{},\"informed_edge_ticks\":{},\"window_steps\":{},\"seed\":{}}},\"dp\":{{\"epsilon_per_window\":{},\"epsilon_total\":{},\"request_cap\":{},\"volume_cap\":{},\"debias\":{}}},\"rows\":[",
        cfg.steps, cfg.step_ms, cfg.n_mm, cfg.n_entities, cfg.wallets_per_entity,
        cfg.ref_mid0, cfg.sigma_ticks, cfg.arrival_rate, cfg.informed_base,
        cfg.informed_ar, cfg.informed_sd, cfg.informed_edge_ticks, cfg.window_steps,
        cfg.seed, dp.epsilon_per_window, dp.epsilon_total, dp.request_cap,
        dp.volume_cap, dp.debias
    );
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            payload.push(',');
        }
        payload.push_str(&row_json(row));
    }
    payload.push_str("]}\n");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(&out, payload).map_err(|error| error.to_string())?;
    println!("wrote {} ({} arms)", out.display(), rows.len());
    Ok(())
}
