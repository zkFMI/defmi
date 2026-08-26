//! The detection figures are the paper's central claim, so they are pinned to
//! what the Python produced rather than to what this port happens to compute.

use qomm_sim::attackers as a;
use qomm_sim::disclosure::Disclosure;
use qomm_sim::engine::{run_arm, ArmOptions, ArmResult, Probe};
use qomm_sim::market::*;

fn arm(protocol: &str) -> (SimConfig, ReferenceMarket, ArmResult) {
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
    let mut disclosure = Disclosure::None;
    let mut options = ArmOptions::new(protocol, 99);
    options.probes = probes;
    let result = run_arm(&cfg, &market, &requests, &makers, &mut disclosure, &options);
    (cfg, market, result)
}

fn close(a: Option<f64>, b: f64) -> bool {
    a.is_some_and(|v| (v - b).abs() < 1e-12)
}

/// The plain arm's detection rises with how much of the wallet-to-entity map the
/// adversary already holds. That is a statement about the adversary.
#[test]
fn the_plain_arm_tracks_the_adversarys_prior_attribution() {
    let (cfg, _, result) = arm("plain_rfq");
    for (rho, expected) in [
        (0.0, 0.5),
        (0.25, 0.712_121_212_121_212_1),
        (0.5, 0.803_030_303_030_303),
        (1.0, 1.0),
    ] {
        let report = a::passive_observer(&result, &cfg, rho, 7);
        assert!(close(report.auc, expected), "rho {rho}: {:?}", report.auc);
    }
}

/// The query-oblivious arm reads exactly 0.500 at every level of attribution,
/// because the channel it leaves is empty and every score ties. This is the one
/// number the whole design is for.
#[test]
fn the_oblivious_arm_is_exactly_one_half_at_every_prior() {
    let (cfg, _, result) = arm("qomm_rfq");
    for rho in [0.0, 0.25, 0.5, 1.0] {
        let report = a::passive_observer(&result, &cfg, rho, 7);
        assert_eq!(report.auc, Some(0.5), "rho {rho}");
        assert!(close(report.tpr_at_5pct_fpr, 0.05));
        // The adversary still holds the same wallets; what changed is that
        // there is nothing for them to be attached to.
        if rho == 1.0 {
            assert_eq!(report.extra["entities_covered"], Some(24.0));
            assert_eq!(report.extra["wallets_linked"], Some(72.0));
        }
    }
}

#[test]
fn direction_and_size_fall_to_the_population_prior_when_hidden() {
    let (cfg, _, plain) = arm("plain_rfq");
    let (_, _, oblivious) = arm("qomm_rfq");
    let p = a::pretrade_attributes(&plain, &cfg);
    let o = a::pretrade_attributes(&oblivious, &cfg);
    assert!(close(p.extra["direction_accuracy"], 1.0));
    assert!(close(p.extra["size_bucket_accuracy"], 1.0));
    assert!(close(o.extra["direction_accuracy"], 0.5));
    assert!(close(o.extra["direction_prior"], 0.5));
    assert_eq!(o.extra["direction_accuracy"], o.extra["direction_prior"]);
    assert_eq!(
        o.extra["size_bucket_accuracy"],
        o.extra["size_bucket_prior"]
    );
    assert_eq!(p.n_examples, 140);
    assert_eq!(o.n_examples, p.n_examples);
}

/// Probing survives obliviousness: a firm price is what the venue returns by
/// design, so the correlation is identical in both arms. Only the per-maker
/// recovery goes away, and only because a plain protocol answered per maker.
#[test]
fn probing_recovers_aggregate_inventory_in_both_arms() {
    let (_, _, plain) = arm("plain_rfq");
    let (_, _, oblivious) = arm("qomm_rfq");
    let p = a::probing_entity(&plain, 64);
    let o = a::probing_entity(&oblivious, 64);
    assert!(
        close(
            p.extra["net_inventory_corr_from_best_quote"],
            0.908_689_438_746_2
        ) || (p.extra["net_inventory_corr_from_best_quote"].unwrap() - 0.9086894387).abs() < 1e-9
    );
    assert_eq!(
        p.extra["net_inventory_corr_from_best_quote"],
        o.extra["net_inventory_corr_from_best_quote"]
    );
    assert!(p.extra["own_inventory_corr_from_per_mm_quotes"].unwrap() > 0.99);
    assert_eq!(o.extra["own_inventory_corr_from_per_mm_quotes"], None);
}

/// Informed-flow detection from settlements is unchanged by hiding requests,
/// because settlements are visible in every arm.
#[test]
fn informed_flow_detection_is_the_same_in_both_arms() {
    let (cfg, market, plain) = arm("plain_rfq");
    let (_, _, oblivious) = arm("qomm_rfq");
    let p = a::external_info_observer(&plain, &cfg, &market);
    let o = a::external_info_observer(&oblivious, &cfg, &market);
    assert!(close(p.auc, 0.791_115_134_865_134_9) || (p.auc.unwrap() - 0.7911151349).abs() < 1e-9);
    assert_eq!(p.auc, o.auc);
    assert_eq!(p.n_examples, 466);
}

/// A rank statistic over entirely tied scores has to come out at exactly one
/// half, and the detection rate at a fixed false-positive rate has to come out
/// at exactly that rate. Anything else means ties are being broken by input
/// order, which would make an empty channel look leaky.
#[test]
fn tied_scores_degenerate_rather_than_leak() {
    let scores = vec![0.0; 200];
    let labels: Vec<u8> = (0..200).map(|i| u8::from(i % 5 == 0)).collect();
    assert_eq!(a::auc(&scores, &labels), Some(0.5));
    assert!(close(a::tpr_at_fpr(&scores, &labels, 0.05), 0.05));
}
