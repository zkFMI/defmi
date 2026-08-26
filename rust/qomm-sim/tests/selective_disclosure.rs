use std::collections::BTreeSet;

use qomm_sim::disclosure::{Disclosure, DpDisclosure};
use qomm_sim::engine::{run_arm, ArmOptions, Probe};
use qomm_sim::market::{MarketMaker, ReferenceMarket, Request, SimConfig};

fn maker(mm_id: usize, kappa: f64, inv_limit: i64) -> MarketMaker {
    MarketMaker {
        mm_id,
        base_half: 0,
        slope: 0,
        inv_coef: 0,
        max_qty: 100,
        kappa,
        inv_limit,
        inventory: 0,
        fills: 0,
        realized_pnl: 0.0,
        quoting: true,
        skew_cap: None,
    }
}

/// The second window is closed through `run_arm`: maker 0 receives the first
/// window's high-imbalance release, while maker 1 must retain its private prior
/// both in probe pricing and in the depth snapshot used by the next release.
#[test]
fn a_disclosure_can_reach_one_maker_without_reaching_another() {
    let cfg = SimConfig {
        steps: 4,
        window_steps: 2,
        n_mm: 3,
        n_entities: 1,
        ..SimConfig::default()
    };
    let market = ReferenceMarket {
        mid: vec![100_000; cfg.steps + 1],
        phi: vec![0.30; cfg.steps + 1],
    };
    // Maker 2 wins the first request and crosses its inventory limit. Makers 0
    // and 1 are otherwise identical, so only selective disclosure can separate
    // their second-window quotes.
    let makers = vec![
        maker(0, 10.0, 1_000),
        maker(1, 10.0, 1_000),
        maker(2, 0.0, 50),
    ];
    let requests = [Request {
        step: 0,
        entity: 0,
        wallet: 0,
        size: 100,
        direction: 0,
        informed: true,
        signal: 1,
    }];
    let mut mechanism = DpDisclosure::new(25_600.0, 3, 100, 1, 1e9, false);
    mechanism.reaches = Some(BTreeSet::from([0]));
    let mut disclosure = Disclosure::Dp(Box::new(mechanism));
    let mut options = ArmOptions::new("plain_rfq", 3);
    options.probes = vec![Probe {
        step: 2,
        size: 100,
        wallet: 10_000,
        entity: 1,
    }];

    let result = run_arm(&cfg, &market, &requests, &makers, &mut disclosure, &options);
    assert_eq!(result.windows.len(), 2);
    assert!(result.releases.iter().all(|release| release.published));

    let quotes = result.probe_results[0].per_mm_quotes.as_ref().unwrap();
    assert!(quotes[&0].0 - 100_000 > 50, "subscriber should widen");
    assert!(
        quotes[&1].0 - 100_000 <= 50,
        "non-subscriber should not widen"
    );
    assert_eq!(
        result.windows[1].makers_in_band, 1,
        "the depth snapshot must not turn a subscriber-only release venue-wide"
    );
    assert_eq!(result.windows[1].liquidity_lots_in_band, 100);
}
