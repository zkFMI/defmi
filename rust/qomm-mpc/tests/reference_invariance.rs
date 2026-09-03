use qomm_mpc::inputs::{build_inputs, finish_reference, InputConfig};
use qomm_mpc::program::{sentinel_for, CheckMode, Mode, Reference};
use serde_json::Value;

const BASE: i128 = 100_000;
const MOVES: [i128; 7] = [0, 1, 5, 50, 500, -7, -300];

fn answer(reference: i128, direction: i128, seed: i128, use_ref: i128) -> Value {
    let references = [reference];
    let config = InputConfig {
        n_mm: 16,
        n_real_mm: 16,
        n_parties: 7,
        is_real: 1,
        n_requests: 1,
        n_assets: 1,
        ref_table: &references,
        user_asset: 0,
        user_qty: 40,
        user_dir: direction,
        user_entity: 0,
        now_t: 1_000,
        seed,
        audit_gates: false,
        value_bits: 31,
        field_bits: 128,
        use_ref,
        reference: Reference::Anchored,
        input_check: false,
        check_mode: CheckMode::Aggregate,
        binding_limit: false,
        user_limit: 100_000,
        user_limit_blinding: 1,
        user_qty_blinding: 1,
        response_mask: None,
        fill_mask: None,
        check_coefficients: &[],
        check_repeats: 7,
        policies: None,
        shamir_inputs: false,
        shamir_threshold: 2,
        dvp: None,
        quote_proof: None,
    };
    let mut generated = build_inputs(&config).unwrap();
    let sentinel = sentinel_for(31, 16, 8 * reference).unwrap();
    finish_reference(&mut generated, &config, sentinel, Mode::Rfq).unwrap();
    serde_json::from_str(&generated.reference_json()).unwrap()
}

fn integer(value: &Value) -> i128 {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .unwrap()
}

#[test]
fn winner_is_invariant_to_the_reference() {
    for direction in [0, 1] {
        for seed in [7, 11, 23, 99, 1_234] {
            let winners = MOVES
                .map(|movement| integer(&answer(BASE + movement, direction, seed, 1)["best_mm"]))
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(winners.len(), 1, "direction {direction}, seed {seed}");
        }
    }
}

#[test]
fn price_is_affine_in_the_reference() {
    for direction in [0, 1] {
        let sign = if direction == 0 { 1 } else { -1 };
        for seed in [7, 11, 23, 99, 1_234] {
            let residuals = MOVES
                .map(|movement| {
                    let reference = BASE + movement;
                    integer(&answer(reference, direction, seed, 1)["best_cost"]) - sign * reference
                })
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(residuals.len(), 1, "direction {direction}, seed {seed}");
        }
    }
}

#[test]
fn the_correction_is_what_a_late_quote_needs() {
    for direction in [0, 1] {
        let sign = if direction == 0 { 1 } else { -1 };
        let started = answer(BASE, direction, 31, 1);
        for drift in [3, 40, -25] {
            let direct = answer(BASE + drift, direction, 31, 1);
            assert_eq!(
                integer(&started["best_cost"]) + sign * drift,
                integer(&direct["best_cost"])
            );
            assert_eq!(started["best_mm"], direct["best_mm"]);
        }
    }
}

#[test]
fn the_cleartext_model_does_not_see_the_sentinel() {
    let sentinel = sentinel_for(31, 16, 8 * BASE).unwrap();
    assert!(sentinel / BASE > 100);
}

#[test]
fn a_narrow_field_is_refused_rather_than_silently_wrong() {
    let error = sentinel_for(16, 16, 8 * BASE).unwrap_err();
    assert!(error.to_string().contains("too narrow"));
}

#[test]
fn a_maker_on_the_reference_tracks_it() {
    for seed in [7, 11, 23] {
        let prices =
            [0, 50, 500].map(|movement| integer(&answer(BASE + movement, 0, seed, 1)["best_cost"]));
        assert_eq!(prices[1] - prices[0], 50);
        assert_eq!(prices[2] - prices[0], 500);
    }
}

#[test]
fn a_maker_off_the_reference_does_not() {
    for seed in [7, 11, 23] {
        let prices = [0, 50, 500, -300]
            .map(|movement| integer(&answer(BASE + movement, 0, seed, 0)["best_cost"]))
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(prices.len(), 1, "seed {seed}");
    }
}

#[test]
fn switching_the_reference_off_does_not_change_who_wins() {
    for seed in [7, 11, 23] {
        let on = answer(BASE, 0, seed, 1);
        let off = answer(BASE, 0, seed, 0);
        assert_eq!(on["best_mm"], off["best_mm"]);
        assert_eq!(integer(&on["best_cost"]) - integer(&off["best_cost"]), BASE);
    }
}

#[test]
fn mixing_the_switch_inside_one_market_costs_the_invariance() {
    let quote = |use_ref: i128, ask_level: i128, reference: i128| use_ref * reference + ask_level;
    let winners = [99_980, 100_000, 100_020, 100_040]
        .map(|reference| {
            if quote(1, 30, reference) < quote(0, 100_020, reference) {
                "relative"
            } else {
                "absolute"
            }
        })
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        winners,
        std::collections::BTreeSet::from(["relative", "absolute"])
    );
}
