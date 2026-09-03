use std::collections::BTreeSet;

use qomm_sim::attackers::linked_wallets;
use qomm_sim::market::SimConfig;

fn config() -> SimConfig {
    SimConfig {
        n_entities: 24,
        wallets_per_entity: 3,
        ..SimConfig::default()
    }
}

fn wallet_count() -> usize {
    config().n_entities * config().wallets_per_entity
}

#[test]
fn no_linkage_means_no_wallets() {
    assert!(linked_wallets(&config(), 0.0, 0).is_empty());
}

#[test]
fn full_linkage_means_every_wallet() {
    assert_eq!(
        linked_wallets(&config(), 1.0, 0),
        (0..wallet_count()).collect()
    );
}

#[test]
fn realised_fraction_matches_the_request() {
    for rho in [0.05, 0.1, 0.12, 0.25, 0.33, 0.5, 0.66, 0.75, 0.9] {
        let linked = linked_wallets(&config(), rho, 7);
        let expected = qomm_sim::market::round_half_even(rho * wallet_count() as f64) as usize;
        assert_eq!(linked.len(), expected, "rho {rho}");
        assert!(
            (linked.len() as f64 / wallet_count() as f64 - rho).abs()
                <= 1.0 / wallet_count() as f64,
            "rho {rho}"
        );
    }
}

#[test]
fn distinct_fractions_stay_distinct() {
    let counts = [0.7, 0.75, 0.8, 0.9, 1.0]
        .map(|rho| linked_wallets(&config(), rho, 7).len())
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(counts.len(), 5);
}

#[test]
fn half_the_wallets_is_not_all_the_firms() {
    let cfg = config();
    let covered = linked_wallets(&cfg, 0.5, 7)
        .into_iter()
        .map(|wallet| wallet / cfg.wallets_per_entity)
        .collect::<BTreeSet<_>>();
    assert!(covered.len() < cfg.n_entities);
}

#[test]
fn no_slot_bias_inside_an_entity() {
    let cfg = config();
    for rho in [0.2, 0.33, 0.5] {
        let slots = linked_wallets(&cfg, rho, 11)
            .into_iter()
            .map(|wallet| wallet % cfg.wallets_per_entity)
            .collect::<BTreeSet<_>>();
        assert_eq!(slots, BTreeSet::from([0, 1, 2]), "rho {rho}");
    }
}

#[test]
fn sampling_reproduces_and_varies_with_the_seed() {
    assert_eq!(
        linked_wallets(&config(), 0.3, 1),
        linked_wallets(&config(), 0.3, 1)
    );
    assert_ne!(
        linked_wallets(&config(), 0.3, 1),
        linked_wallets(&config(), 0.3, 2)
    );
}

#[test]
fn coverage_rises_monotonically_with_rho() {
    let cfg = config();
    let mut previous = 0;
    for rho in [0.0, 0.1, 0.25, 0.5, 0.75, 1.0] {
        let covered = linked_wallets(&cfg, rho, 3)
            .into_iter()
            .map(|wallet| wallet / cfg.wallets_per_entity)
            .collect::<BTreeSet<_>>()
            .len();
        assert!(covered >= previous, "rho {rho}: {covered} < {previous}");
        previous = covered;
    }
}
