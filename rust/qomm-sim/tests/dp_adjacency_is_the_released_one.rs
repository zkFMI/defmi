use std::collections::BTreeMap;

use qomm_sim::audit::{audit_window, clopper_pearson, drop_entity, AuditSettings, Field};
use qomm_sim::disclosure::{
    discrete_laplace, DpDisclosure, EntityAccountant, ReleaseFields, WindowObservation,
};
use qomm_sim::pyrandom::PyRandom;

fn window(
    fills_by_entity: &[(usize, i64)],
    requests_by_entity: &[(usize, i64)],
) -> WindowObservation {
    let requests: BTreeMap<usize, i64> = requests_by_entity.iter().copied().collect();
    let fills: BTreeMap<usize, i64> = fills_by_entity.iter().copied().collect();
    WindowObservation {
        window: 0,
        start_step: 0,
        end_step: 100,
        requests_by_entity: requests.clone(),
        volume_by_entity: requests.keys().map(|entity| (*entity, 10)).collect(),
        signed_volume_by_entity: requests.keys().map(|entity| (*entity, 0)).collect(),
        fills_by_entity: fills.clone(),
        fills: fills.values().sum(),
        requests: requests.values().sum(),
        no_quote: 0,
        liquidity_lots_in_band: 5,
        makers_in_band: 3,
        fills_by_bucket: [1, 1, 1],
        requests_by_bucket: [1, 1, 1],
    }
}

fn disclosure(entities: usize, cap: i64) -> DpDisclosure {
    DpDisclosure::new(1.0, cap, 1_000, entities, 1_000.0, true)
}

fn released_fields(obs: &WindowObservation, entities: usize, cap: i64) -> ReleaseFields {
    let mut mechanism = disclosure(entities, cap);
    let release = mechanism.release(obs, &mut PyRandom::new(0));
    assert!(release.published);
    release.fields
}

#[test]
fn removing_one_entity_moves_the_fill_count_by_at_most_its_cap() {
    let entities = 8;
    let requests: Vec<(usize, i64)> = (0..entities).map(|entity| (entity, 100)).collect();
    let fills: Vec<(usize, i64)> = (0..entities)
        .map(|entity| (entity, if entity == 0 { 100 } else { 0 }))
        .collect();
    let obs = window(&fills, &requests);
    let cap = 3;
    let here = released_fields(&obs, entities, cap).exact_fills;
    for victim in 0..entities {
        let there = released_fields(&drop_entity(&obs, victim), entities, cap).exact_fills;
        assert!(
            (here - there).abs() <= cap,
            "dropping entity {victim} moved fills by {}, past cap {}",
            (here - there).abs(),
            cap
        );
    }
}

#[test]
fn the_audits_neighbour_removes_the_entity_from_every_field() {
    let obs = window(&[(0, 7), (1, 2)], &[(0, 9), (1, 5)]);
    let without = drop_entity(&obs, 0);
    assert!(!without.fills_by_entity.contains_key(&0));
    assert!(!without.requests_by_entity.contains_key(&0));
    assert!(!without.volume_by_entity.contains_key(&0));
    assert!(!without.signed_volume_by_entity.contains_key(&0));
    assert_eq!(without.fills_by_entity, BTreeMap::from([(1, 2)]));
    assert_eq!(without.requests_by_entity, BTreeMap::from([(1, 5)]));
    assert_eq!(without.volume_by_entity, BTreeMap::from([(1, 10)]));
    assert_eq!(without.signed_volume_by_entity, BTreeMap::from([(1, 0)]));
    assert_eq!(without.fills, 2);
    assert_eq!(without.requests, 5);
}

#[test]
fn the_fill_field_is_not_more_exposed_than_the_request_field() {
    let entities = 6;
    let requests: Vec<(usize, i64)> = (0..entities).map(|entity| (entity, 30)).collect();
    let obs = window(&[(0, 30), (1, 30)], &requests);
    let here = released_fields(&obs, entities, 3);
    let (fill_move, request_move) = (0..entities)
        .map(|entity| {
            let there = released_fields(&drop_entity(&obs, entity), entities, 3);
            (
                (here.exact_fills - there.exact_fills).abs(),
                (here.exact_requests - there.exact_requests).abs(),
            )
        })
        .fold((0, 0), |(max_fill, max_request), (fill, request)| {
            (max_fill.max(fill), max_request.max(request))
        });
    assert!(fill_move <= request_move);
}

fn published(obs: &WindowObservation) -> bool {
    let mut mechanism = disclosure(2, 3);
    mechanism.accountants.insert(0, {
        let mut account = EntityAccountant::new(1.0);
        account.spend(1.0);
        account
    });
    mechanism
        .accountants
        .insert(1, EntityAccountant::new(1_000.0));
    mechanism.release(obs, &mut PyRandom::new(0)).published
}

#[test]
fn whether_a_window_is_published_does_not_depend_on_who_was_in_it() {
    let with = window(&[(0, 1), (1, 1)], &[(0, 1), (1, 1)]);
    let without = window(&[(1, 1)], &[(1, 1)]);
    assert_eq!(published(&with), published(&without));
    assert!(!published(&with));
}

#[test]
fn the_budget_is_charged_whether_or_not_an_entity_traded() {
    let mut mechanism = disclosure(2, 3);
    mechanism.release(&window(&[(0, 1)], &[(0, 1)]), &mut PyRandom::new(0));
    assert_eq!(mechanism.accountants[&1].releases, 1);
}

#[test]
fn release_refuses_when_any_enrolled_entity_is_out_of_budget() {
    let obs = window(&[(1, 1)], &[(1, 1)]);
    let mut mechanism = disclosure(2, 3);
    let mut exhausted = EntityAccountant::new(1.0);
    exhausted.spend(1.0);
    mechanism.accountants.insert(0, exhausted);
    let release = mechanism.release(&obs, &mut PyRandom::new(0));
    println!(
        "inactive_enrolled_entity_out_of_budget: published={} reason={}",
        release.published, release.suppressed_reason
    );
    assert!(!release.published);
    assert_eq!(release.suppressed_reason, "entity privacy budget exhausted");
}

fn empirical_epsilon(samples_in: &[i64], samples_out: &[i64], claim: f64) -> (f64, bool) {
    let mut candidates: Vec<i64> = samples_in.iter().chain(samples_out).copied().collect();
    candidates.sort_unstable();
    candidates.dedup();
    let alpha = 0.05 / candidates.len().max(1) as f64;
    let mut best = 0.0f64;
    for threshold in candidates {
        let k_in = samples_in
            .iter()
            .filter(|value| **value >= threshold)
            .count();
        let k_out = samples_out
            .iter()
            .filter(|value| **value >= threshold)
            .count();
        let (tpr_lo, _) = clopper_pearson(k_in, samples_in.len(), alpha);
        let (_, fpr_hi) = clopper_pearson(k_out, samples_out.len(), alpha);
        for (numerator, denominator) in [(tpr_lo, fpr_hi), (1.0 - fpr_hi, 1.0 - tpr_lo)] {
            if numerator > 0.0 && denominator > 0.0 {
                best = best.max((numerator / denominator).ln());
            }
        }
    }
    (best, best <= claim + 1e-9)
}

#[test]
fn the_two_world_game_catches_the_clipping_that_broke_the_fill_field() {
    let entities = 8;
    let requests: Vec<(usize, i64)> = (0..entities).map(|entity| (entity, 100)).collect();
    let fills: Vec<(usize, i64)> = (0..entities)
        .map(|entity| (entity, if entity == 0 { 100 } else { 0 }))
        .collect();
    let obs = window(&fills, &requests);
    let settings = AuditSettings {
        epsilon_per_window: 1.0,
        request_cap: 3,
        volume_cap: 300,
        trials: 1_500,
        seed: 1,
        n_entities: entities,
        field: Field::Fills,
        ..AuditSettings::default()
    };
    let fixed = audit_window(&obs, 0, &settings);
    assert!(
        fixed.within_claim,
        "fixed epsilon {}",
        fixed.empirical_epsilon
    );

    let without = drop_entity(&obs, 0);
    let old_clipped = |world: &WindowObservation| {
        let clipped_requests: i64 = world
            .requests_by_entity
            .values()
            .map(|count| (*count).min(3))
            .sum();
        world.fills.min(clipped_requests)
    };
    let mut rng = PyRandom::new(1);
    let samples_in: Vec<i64> = (0..1_500)
        .map(|_| old_clipped(&obs) + discrete_laplace(0.25, 3.0, &mut rng))
        .collect();
    let samples_out: Vec<i64> = (0..1_500)
        .map(|_| old_clipped(&without) + discrete_laplace(0.25, 3.0, &mut rng))
        .collect();
    let (old_epsilon, old_within_claim) = empirical_epsilon(&samples_in, &samples_out, 0.25);
    assert!(!old_within_claim, "old clipping epsilon {old_epsilon}");
    assert!(
        old_epsilon > 4.0 * fixed.empirical_epsilon,
        "old {old_epsilon} vs fixed {}",
        fixed.empirical_epsilon
    );
}
