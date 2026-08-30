use qomm_sim::attackers as a;
use qomm_sim::disclosure::Disclosure;
use qomm_sim::engine::{run_arm, ArmOptions, Probe};
use qomm_sim::market::*;

fn fmt(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.12}")).unwrap_or("None".into())
}

fn main() {
    let cfg = SimConfig {
        steps: 4_000,
        window_steps: 200,
        ..Default::default()
    };
    let market = ReferenceMarket::new(&cfg, cfg.seed);
    let makers = build_market_makers(&cfg, cfg.seed + 1);
    let requests = build_requests(&cfg, &market, cfg.seed + 2);
    let probes: Vec<Probe> = (0..4_000)
        .step_by(8)
        .map(|step| Probe {
            step,
            size: 100,
            wallet: 0,
            entity: 0,
        })
        .collect();

    for protocol in ["plain_rfq", "qomm_rfq"] {
        let mut disclosure = Disclosure::None;
        let mut options = ArmOptions::new(protocol, 99);
        options.probes = probes.clone();
        let r = run_arm(&cfg, &market, &requests, &makers, &mut disclosure, &options);
        for rho in [0.0, 0.25, 0.5, 1.0] {
            let report = a::passive_observer(&r, &cfg, rho, 7);
            println!(
                "{protocol} A1 rho={rho} auc={} tpr={} base={} n={} cov={} linked={}",
                fmt(report.auc),
                fmt(report.tpr_at_5pct_fpr),
                fmt(Some(report.base_rate)),
                report.n_examples,
                report.extra["entities_covered"].unwrap() as i64,
                report.extra["wallets_linked"].unwrap() as i64
            );
        }
        let b = a::pretrade_attributes(&r, &cfg);
        println!(
            "{protocol} A1b dir={} prior={} sz={} n={}",
            fmt(b.extra["direction_accuracy"]),
            fmt(b.extra["direction_prior"]),
            fmt(b.extra["size_bucket_accuracy"]),
            b.n_examples
        );
        let c = a::probing_entity(&r, 64);
        println!(
            "{protocol} A3 net={} per_mm={} n={}",
            fmt(c.extra["net_inventory_corr_from_best_quote"]),
            fmt(c.extra["own_inventory_corr_from_per_mm_quotes"]),
            c.n_examples
        );
        let e = a::external_info_observer(&r, &cfg, &market);
        println!(
            "{protocol} A5 auc={} base={} n={}",
            fmt(e.auc),
            fmt(Some(e.base_rate)),
            e.n_examples
        );
    }
}
