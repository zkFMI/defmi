use qomm_sim::disclosure::EntityAccountant;
use qomm_sim::pyrandom::PyRandom;
use qomm_sim::queries::{
    answer_range_query, answer_range_query_with_eligibility, noise_scale, questions_affordable,
    Pricing, RangeQuery, SENSITIVITY,
};

const QUOTES: [i64; 10] = [
    99_960, 99_970, 99_988, 99_995, 100_000, 100_003, 100_008, 100_015, 100_040, 100_120,
];

fn asker(total: f64) -> EntityAccountant {
    EntityAccountant::new(total)
}

#[test]
fn one_firm_moves_the_count_by_one() {
    let query = RangeQuery::new(99_960, 100_040).unwrap();
    let mut rng = PyRandom::new(11);
    let inside = answer_range_query(&QUOTES, &query, 64.0, &mut asker(1_000.0), &mut rng)
        .unwrap()
        .count
        .unwrap();
    for drop in 0..QUOTES.len() {
        let without_quotes: Vec<i64> = QUOTES
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != drop)
            .map(|(_, quote)| *quote)
            .collect();
        let mut rng = PyRandom::new(11);
        let without =
            answer_range_query(&without_quotes, &query, 64.0, &mut asker(1_000.0), &mut rng)
                .unwrap()
                .count
                .unwrap();
        let expected = i64::from(query.low <= QUOTES[drop] && QUOTES[drop] <= query.high);
        assert_eq!(
            inside - without,
            expected,
            "dropping maker {drop}; sensitivity {SENSITIVITY}"
        );
    }
}

#[test]
fn the_noise_is_small_enough_to_read() {
    assert_eq!(noise_scale(1.0), 1.0);
    assert_eq!(noise_scale(0.25), 4.0);
    let query = RangeQuery::new(99_960, 100_040).unwrap();
    let truth = QUOTES
        .iter()
        .filter(|quote| query.low <= **quote && **quote <= query.high)
        .count() as i64;
    let mut rng = PyRandom::new(7);
    let mut got: Vec<i64> = (0..200)
        .map(|_| {
            answer_range_query(&QUOTES, &query, 1.0, &mut asker(100.0), &mut rng)
                .unwrap()
                .count
                .unwrap()
        })
        .collect();
    got.sort_unstable();
    assert!((got[got.len() / 2] - truth).abs() <= 1);
}

/// The query API exposes only the asker, so it cannot observe or prove anything
/// about other accounts. This test pins the production behavior it can reach.
#[test]
fn the_asker_pays_for_each_answer() {
    let mut rng = PyRandom::new(1);
    let mut new_entrant = asker(5.0);
    let query = RangeQuery::new(0, 1_000_000_000).unwrap();
    for _ in 0..3 {
        let answer = answer_range_query(&QUOTES, &query, 1.0, &mut new_entrant, &mut rng).unwrap();
        assert_eq!(answer.epsilon_spent, 1.0);
        assert!(answer.count.is_some());
    }
    assert_eq!(new_entrant.spent, 3.0);
    assert_eq!(new_entrant.releases, 3);
}

#[test]
fn running_out_says_so_and_says_nothing_about_the_market() {
    let mut rng = PyRandom::new(2);
    let mut spent = asker(1.0);
    spent.spend(1.0);
    let query = RangeQuery::new(0, 1_000_000_000).unwrap();
    let first = answer_range_query(&[1, 2, 3], &query, 1.0, &mut spent, &mut rng).unwrap();
    let busy: Vec<i64> = (100_000..100_050).collect();
    let second = answer_range_query(&busy, &query, 1.0, &mut spent, &mut rng).unwrap();
    assert!(first.count.is_none() && second.count.is_none());
    assert_eq!(first.refused, second.refused);
}

#[test]
fn a_budget_buys_a_countable_number_of_questions() {
    assert_eq!(questions_affordable(10.0, 1.0).unwrap(), 10);
    assert_eq!(questions_affordable(10.0, 0.25).unwrap(), 40);
    assert!(questions_affordable(10.0, 0.0).is_err());
}

#[test]
fn an_empty_or_backwards_range_is_refused() {
    assert!(RangeQuery::new(100, 50).is_err());
}

#[test]
fn only_eligible_makers_are_counted() {
    let mut rng = PyRandom::new(3);
    let query = RangeQuery::new(0, 1_000_000_000).unwrap();
    let eligible = [false; QUOTES.len()];
    let answer = answer_range_query_with_eligibility(
        &QUOTES,
        &query,
        4.0,
        &mut asker(100.0),
        &mut rng,
        Some(&eligible),
    )
    .unwrap();
    assert!(answer.count.unwrap() <= 2);
}

#[test]
fn the_snapshot_is_part_of_the_question() {
    assert_eq!(RangeQuery::new(0, 1).unwrap().snapshot, 0);
    assert_eq!(RangeQuery::with_snapshot(0, 1, 12).unwrap().snapshot, 12);
}

#[test]
fn splitting_a_question_does_not_change_its_price() {
    let pricing = Pricing::default();
    let whole = pricing.price(2.0, 4.0).unwrap();
    let (mut pieces, mut spent) = (0.0, 2.0);
    for _ in 0..8 {
        pieces += pricing.price(spent, 0.5).unwrap();
        spent += 0.5;
    }
    assert!((pieces - whole).abs() <= whole.abs() * 1e-12);
}

#[test]
fn the_price_rises_steeply_with_what_has_been_learned() {
    let pricing = Pricing::default();
    let locating = pricing.total_for(7.0).unwrap();
    let extracting = pricing.total_for(30.0).unwrap();
    assert!(extracting / locating > 10_000.0);
    let marginals: Vec<f64> = (0..30)
        .map(|spent| pricing.price(spent as f64, 1.0).unwrap())
        .collect();
    assert!(marginals.windows(2).all(|pair| pair[0] <= pair[1]));
}

#[test]
fn the_ceiling_is_not_for_sale() {
    let pricing = Pricing {
        epsilon_max: 10.0,
        ..Default::default()
    };
    assert!(pricing.affordable(9.0, 1e12, 0.5));
    let mut account = asker(pricing.epsilon_max);
    let mut rng = PyRandom::new(13);
    let query = RangeQuery::new(0, 1_000_000_000).unwrap();
    for _ in 0..9 {
        assert!(
            answer_range_query(&QUOTES, &query, 1.0, &mut account, &mut rng)
                .unwrap()
                .count
                .is_some()
        );
    }
    let answer = answer_range_query(&QUOTES, &query, 2.0, &mut account, &mut rng).unwrap();
    assert!(answer.count.is_none());
    assert_eq!(answer.epsilon_spent, 0.0);
    assert!(answer.refused.unwrap().contains("budget"));
    assert_eq!(account.spent, 9.0);
    assert_eq!(account.releases, 9);
}
