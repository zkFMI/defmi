use qomm_sim::disclosure::{Disclosure, DpDisclosure};
use qomm_sim::engine::{run_arm, ArmOptions};
use qomm_sim::market::*;

fn main() {
    let cfg = SimConfig {
        steps: 4_000,
        window_steps: 200,
        ..Default::default()
    };
    let market = ReferenceMarket::new(&cfg, cfg.seed);
    let makers = build_market_makers(&cfg, cfg.seed + 1);
    let requests = build_requests(&cfg, &market, cfg.seed + 2);

    for protocol in ["plain_rfq", "qomm_rfq"] {
        for (name, mut disclosure) in [
            ("A", Disclosure::None),
            (
                "B",
                Disclosure::Threshold {
                    min_makers: 5,
                    min_lots: 800,
                },
            ),
            (
                "C",
                Disclosure::Dp(Box::new(DpDisclosure::new(
                    1.0,
                    3,
                    300,
                    cfg.n_entities,
                    40.0,
                    true,
                ))),
            ),
        ] {
            let mut options = ArmOptions::new(protocol, 99);
            options.reactive = true;
            let r = run_arm(&cfg, &market, &requests, &makers, &mut disclosure, &options);
            println!(
                "{protocol} {name} fills={} noq={} rej={} cost_med={} pnl={:.6} \
                      cont={:.9} supp={:.6} obs={} set={} win={} eps={:.6}",
                r.fills,
                r.no_quote,
                r.rejected,
                r.user_cost_median()
                    .map(|v| format!("{v}"))
                    .unwrap_or("None".into()),
                r.mm_pnl_total(),
                r.quote_continuation,
                r.suppression_rate,
                r.observations.len(),
                r.settlements.len(),
                r.windows.len(),
                r.epsilon_spent_max
            );
        }
    }
}
