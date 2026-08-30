use qomm_sim::deterministic_random::DeterministicRng;
use qomm_sim::disclosure::{EntityAccountant, WindowObservation};
use qomm_sim::queries::{
    answer_block_range_query, answer_block_range_query_at, event_count_sensitivity,
    expected_distinct, informative_span, noise_scale, windows_in_range, BlockRangeQuery,
    DEFAULT_SETTLEMENT_LAG, SENSITIVITY,
};

fn ledger(per_window: &[Vec<usize>], width: usize) -> Vec<WindowObservation> {
    per_window
        .iter()
        .enumerate()
        .map(|(window, entities)| WindowObservation {
            window,
            start_step: window * width,
            end_step: window * width + width - 1,
            requests_by_entity: entities.iter().map(|entity| (*entity, 3)).collect(),
            ..WindowObservation::default()
        })
        .collect()
}

fn asker(total: f64) -> EntityAccountant {
    EntityAccountant::new(total)
}

fn exact_block_count(windows: &[WindowObservation], query: &BlockRangeQuery) -> i64 {
    let mut rng = DeterministicRng::new(7);
    answer_block_range_query(windows, query, 64.0, &mut asker(1_000.0), &mut rng)
        .count
        .unwrap()
}

#[test]
fn sensitivity_is_flat_in_the_range_width() {
    for width in [1usize, 5, 10, 40] {
        let with_entity = ledger(&vec![vec![1, 2, 3]; width], 100);
        let without_entity = ledger(&vec![vec![1, 3]; width], 100);
        let query = BlockRangeQuery::new(0, width * 100 - 1).unwrap();
        let movement =
            exact_block_count(&with_entity, &query) - exact_block_count(&without_entity, &query);
        assert_eq!(movement, SENSITIVITY, "width {width}");
    }
}

#[test]
fn an_event_count_would_grow_with_the_range() {
    assert_eq!(event_count_sensitivity(1, 3).unwrap(), 3);
    assert_eq!(event_count_sensitivity(40, 3).unwrap(), 120);
    assert_eq!(noise_scale(1.0), 1.0);
    assert_eq!(event_count_sensitivity(40, 3).unwrap() as f64, 120.0);
}

#[test]
fn the_answer_names_the_windows_it_covered() {
    let windows = ledger(&[vec![1], vec![2], vec![3], vec![4]], 100);
    let mut rng = DeterministicRng::new(0);
    let answer = answer_block_range_query(
        &windows,
        &BlockRangeQuery::new(150, 349).unwrap(),
        1.0,
        &mut asker(100.0),
        &mut rng,
    );
    assert_eq!(answer.covered, Some((2, 2)));
}

#[test]
fn a_partly_covered_window_is_not_counted() {
    let windows = ledger(&[vec![1, 2, 3]], 100);
    assert!(windows_in_range(&windows, &BlockRangeQuery::new(0, 98).unwrap()).is_empty());
    assert_eq!(
        windows_in_range(&windows, &BlockRangeQuery::new(0, 99).unwrap()).len(),
        1
    );
}

#[test]
fn a_range_with_no_whole_window_is_refused_and_free() {
    let windows = ledger(&[vec![1, 2]], 100);
    let mut account = asker(100.0);
    let mut rng = DeterministicRng::new(0);
    let answer = answer_block_range_query(
        &windows,
        &BlockRangeQuery::new(0, 10).unwrap(),
        1.0,
        &mut account,
        &mut rng,
    );
    assert!(answer.count.is_none());
    assert_eq!(answer.epsilon_spent, 0.0);
    assert_eq!(account.spent, 0.0);
    assert!(answer.refused.unwrap().contains("whole window"));
}

#[test]
fn the_live_range_is_refused() {
    let windows = ledger(&vec![vec![1]; 5], 100);
    let query = BlockRangeQuery::new(0, 499).unwrap();
    for (case, now) in [
        (
            "inside the settlement-lag boundary",
            Some(query.to_block + DEFAULT_SETTLEMENT_LAG - 1),
        ),
        ("current block is unknown", None),
        (
            "chain height is below the lag",
            Some(DEFAULT_SETTLEMENT_LAG - 1),
        ),
    ] {
        let mut rng = DeterministicRng::new(0);
        let mut account = asker(100.0);
        let answer = answer_block_range_query_at(
            &windows,
            &query,
            1.0,
            &mut account,
            &mut rng,
            now,
            DEFAULT_SETTLEMENT_LAG,
        );
        assert!(answer.count.is_none(), "{case}");
        assert_eq!(answer.epsilon_spent, 0.0, "{case}");
        assert_eq!(account.spent, 0.0, "{case}");
        assert!(answer.refused.unwrap().contains("last"), "{case}");
    }
}

#[test]
fn refusing_on_budget_is_a_fact_about_the_asker() {
    let windows = ledger(&[vec![1, 2]], 100);
    let mut rng = DeterministicRng::new(0);
    let answer = answer_block_range_query(
        &windows,
        &BlockRangeQuery::new(0, 99).unwrap(),
        1.0,
        &mut asker(0.5),
        &mut rng,
    );
    assert!(answer.count.is_none());
    assert!(answer.refused.unwrap().contains("asker"));
}

#[test]
fn the_market_never_changes_whether_it_answers() {
    for entities in [0usize, 1, 50, 51, 64, 128, 1_000] {
        let market: Vec<usize> = (0..entities).collect();
        let windows = ledger(&vec![market; 4], 100);
        let mut rng = DeterministicRng::new(0);
        let answer = answer_block_range_query(
            &windows,
            &BlockRangeQuery::new(0, 399).unwrap(),
            1.0,
            &mut asker(100.0),
            &mut rng,
        );
        assert!(answer.refused.is_none(), "{entities} entities");
        assert_eq!(answer.covered, Some((0, 3)), "{entities} entities");
    }
}

#[test]
fn the_noise_matches_the_sensitivity_one_scale() {
    let p = (-1.0f64).exp();
    let want = (2.0 * p).sqrt() / (1.0 - p);
    let entities: Vec<usize> = (0..50).collect();
    for width in [1usize, 5, 10, 40] {
        let windows = ledger(&vec![entities.clone(); width], 100);
        let query = BlockRangeQuery::new(0, width * 100 - 1).unwrap();
        let mut rng = DeterministicRng::new(20_260_824);
        let mut account = asker(1e9);
        let draws: Vec<f64> = (0..4_000)
            .map(|_| {
                answer_block_range_query(&windows, &query, 1.0, &mut account, &mut rng)
                    .count
                    .unwrap() as f64
                    - entities.len() as f64
            })
            .collect();
        let got = (draws.iter().map(|draw| draw * draw).sum::<f64>() / draws.len() as f64).sqrt();
        assert!(
            (got - want).abs() < 0.15 * want,
            "width {width}: {got} against {want}"
        );
    }
}

#[test]
fn the_count_saturates_at_the_enrolment() {
    assert_eq!(expected_distinct(24, 0.2, 0).unwrap(), 0.0);
    assert!((expected_distinct(24, 0.2, 10_000).unwrap() - 24.0).abs() < 1e-12);
    assert!(expected_distinct(24, 0.2, 5).unwrap() < expected_distinct(24, 0.2, 10).unwrap());
}

#[test]
fn a_venue_can_have_no_width_worth_buying() {
    let (lower, upper) = informative_span(24, 0.2, 1.0).unwrap();
    assert!(lower <= upper);
    let (tiny_lower, tiny_upper) = informative_span(2, 0.9, 0.05).unwrap();
    assert!(tiny_lower > tiny_upper);
}

#[test]
fn an_empty_range_is_not_a_question() {
    assert!(BlockRangeQuery::new(500, 499).is_err());
}

#[test]
fn distinct_entity_and_event_sensitivities_are_printed_at_required_widths() {
    let cap = 3;
    for width in [1usize, 5, 10, 40] {
        let with_entity = ledger(&vec![vec![0, 1]; width], 100);
        let without_entity = ledger(&vec![vec![0]; width], 100);
        let query = BlockRangeQuery::new(0, width * 100 - 1).unwrap();
        let distinct =
            exact_block_count(&with_entity, &query) - exact_block_count(&without_entity, &query);
        let events = event_count_sensitivity(width, cap).unwrap();
        println!("width={width} distinct_entity_sensitivity={distinct} event_count_sensitivity={events} (cap*windows={cap}*{width})");
        assert_eq!(distinct, SENSITIVITY);
        assert_eq!(events, cap * width as i64);
    }
}
