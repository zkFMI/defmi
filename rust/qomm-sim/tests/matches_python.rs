//! The port is only worth having if it is the same simulation, so the expected
//! values below are what CPython produces, pasted in rather than recomputed.
//!
//! Regenerate with:
//!   python3 -c "import random; r = random.Random(0); print([r.random() for _ in range(4)])"
//! and the equivalents for the market, from `mvp/qomm/qomm_sim/market.py`.

use qomm_sim::market::*;
use qomm_sim::pyrandom::PyRandom;

const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME: u64 = 1_099_511_628_211;

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

fn hash_u64(hash: &mut u64, value: u64) {
    hash_bytes(hash, &value.to_le_bytes());
}

fn hash_i64(hash: &mut u64, value: i64) {
    hash_bytes(hash, &value.to_le_bytes());
}

fn hash_f64(hash: &mut u64, value: f64) {
    hash_bytes(hash, &value.to_le_bytes());
}

fn hash_bool(hash: &mut u64, value: bool) {
    hash_bytes(hash, &[u8::from(value)]);
}

fn hash_str(hash: &mut u64, value: &str) {
    hash_u64(hash, value.len() as u64);
    hash_bytes(hash, value.as_bytes());
}

fn price_path_fingerprint(mid: &[i64]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash_u64(&mut hash, mid.len() as u64);
    for value in mid {
        hash_i64(&mut hash, *value);
    }
    hash
}

fn makers_fingerprint(makers: &[MarketMaker]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash_u64(&mut hash, makers.len() as u64);
    for maker in makers {
        hash_u64(&mut hash, maker.mm_id as u64);
        for value in [maker.base_half, maker.slope, maker.inv_coef, maker.max_qty] {
            hash_i64(&mut hash, value);
        }
        hash_f64(&mut hash, maker.kappa);
        hash_i64(&mut hash, maker.inv_limit);
        hash_i64(&mut hash, maker.inventory);
        hash_u64(&mut hash, maker.fills);
        hash_f64(&mut hash, maker.realized_pnl);
        hash_bool(&mut hash, maker.quoting);
        hash_bool(&mut hash, maker.skew_cap.is_some());
        if let Some(cap) = maker.skew_cap {
            hash_i64(&mut hash, cap);
        }
    }
    hash
}

fn requests_fingerprint(requests: &[Request]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash_u64(&mut hash, requests.len() as u64);
    for request in requests {
        for value in [request.step, request.entity, request.wallet] {
            hash_u64(&mut hash, value as u64);
        }
        hash_i64(&mut hash, request.size);
        hash_bytes(&mut hash, &[request.direction]);
        hash_bool(&mut hash, request.informed);
        hash_i64(&mut hash, request.signal);
    }
    hash
}

fn hash_entity_map(hash: &mut u64, map: &std::collections::BTreeMap<usize, i64>) {
    hash_u64(hash, map.len() as u64);
    for (entity, value) in map {
        hash_u64(hash, *entity as u64);
        hash_i64(hash, *value);
    }
}

fn entity_fields_fingerprint(windows: &[qomm_sim::disclosure::WindowObservation]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash_u64(&mut hash, windows.len() as u64);
    for window in windows {
        hash_u64(&mut hash, window.window as u64);
        for map in [
            &window.requests_by_entity,
            &window.volume_by_entity,
            &window.signed_volume_by_entity,
            &window.fills_by_entity,
        ] {
            hash_entity_map(&mut hash, map);
        }
    }
    hash
}

fn releases_fingerprint(releases: &[qomm_sim::disclosure::Release]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash_u64(&mut hash, releases.len() as u64);
    for release in releases {
        let fields = &release.fields;
        hash_u64(&mut hash, release.window as u64);
        hash_str(&mut hash, release.mode);
        hash_bool(&mut hash, release.published);
        for value in [
            fields.noisy_requests,
            fields.noisy_volume,
            fields.noisy_signed_volume,
            fields.noisy_fills,
        ] {
            hash_i64(&mut hash, value);
        }
        hash_bool(&mut hash, fields.fill_rate.is_some());
        if let Some(fill_rate) = fields.fill_rate {
            hash_f64(&mut hash, fill_rate);
        }
        for value in [
            fields.exact_requests,
            fields.exact_volume,
            fields.exact_signed_volume,
            fields.exact_fills,
            fields.request_cap,
            fields.volume_cap,
        ] {
            hash_i64(&mut hash, value);
        }
        hash_f64(&mut hash, fields.noise_scale_requests);
        hash_f64(&mut hash, fields.noise_scale_signed);
        hash_bool(&mut hash, fields.debiased);
        hash_i64(&mut hash, fields.min_makers);
        hash_i64(&mut hash, fields.min_lots);
        hash_f64(&mut hash, release.epsilon_spent);
        hash_str(&mut hash, release.suppressed_reason);
    }
    hash
}

#[test]
fn the_uniform_stream_is_cpythons() {
    let mut r = PyRandom::new(0);
    let expected = [
        0.844_421_851_525_048_1,
        0.757_954_402_940_302_5,
        0.420_571_580_830_845,
        0.258_916_750_292_963_35,
    ];
    for want in expected {
        assert_eq!(r.random(), want);
    }
}

#[test]
fn the_integer_draws_are_cpythons() {
    let mut r = PyRandom::new(0);
    for _ in 0..4 {
        r.random();
    }
    assert_eq!(
        [
            r.getrandbits(8),
            r.getrandbits(8),
            r.getrandbits(8),
            r.getrandbits(8)
        ],
        [130, 124, 103, 235]
    );
    assert_eq!(
        [r.getrandbits(40), r.getrandbits(40), r.getrandbits(40)],
        [913_899_456_057, 1_062_159_640_329, 392_888_992_260]
    );
    assert_eq!(
        (0..6).map(|_| r.randint(6, 18)).collect::<Vec<_>>(),
        vec![15, 9, 14, 8, 10, 8]
    );
    let pool = [0i64, 0, 1, 1, 2];
    assert_eq!(
        (0..6).map(|_| *r.choice(&pool)).collect::<Vec<_>>(),
        vec![0, 2, 1, 2, 2, 0]
    );
    assert_eq!(
        (0..8)
            .map(|_| r.choices(&[0.55, 0.33, 0.12]))
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 1, 0, 0, 0, 1]
    );
}

#[test]
fn sample_takes_the_same_subset() {
    let mut r = PyRandom::new(0);
    for _ in 0..4 {
        r.random();
    }
    for _ in 0..4 {
        r.getrandbits(8);
    }
    for _ in 0..3 {
        r.getrandbits(40);
    }
    for _ in 0..6 {
        r.randint(6, 18);
    }
    let pool = [0i64, 0, 1, 1, 2];
    for _ in 0..6 {
        r.choice(&pool);
    }
    for _ in 0..8 {
        r.choices(&[0.55, 0.33, 0.12]);
    }
    for _ in 0..5 {
        r.gauss(0.0, 6.0);
    }
    for _ in 0..3 {
        r.paretovariate(1.6);
    }
    for _ in 0..3 {
        r.uniform(1.5, 4.0);
    }
    assert_eq!(
        r.sample(72, 12),
        vec![0, 63, 42, 31, 41, 8, 24, 28, 30, 51, 61, 9]
    );
}

/// The Gaussian goes through libm, where the last bit can differ between two
/// runtimes. What matters is whether that reaches the simulation, and it does
/// not: the price path is in integer ticks and it agrees exactly.
#[test]
fn the_price_path_agrees_in_ticks_over_a_full_run() {
    let cfg = SimConfig::default();
    let market = ReferenceMarket::new(&cfg, cfg.seed);
    assert_eq!(market.mid.len(), cfg.steps + 1);
    assert_eq!(price_path_fingerprint(&market.mid), 0xf86c_2fa0_e09e_a909);
    assert_eq!(
        &market.mid[market.mid.len() - 8..],
        &[99_500, 99_497, 99_498, 99_503, 99_503, 99_500, 99_500, 99_496]
    );
    assert_eq!(market.phi[0], 0.30);
}

#[test]
fn the_makers_are_the_same_makers() {
    let cfg = SimConfig {
        steps: 4_000,
        ..Default::default()
    };
    let makers = build_market_makers(&cfg, cfg.seed + 1);
    assert_eq!(makers.len(), cfg.n_mm);
    assert_eq!(makers_fingerprint(&makers), 0x9905_e6c3_aeef_d7a7);
}

#[test]
fn the_request_stream_is_the_same_stream() {
    let cfg = SimConfig {
        steps: 4_000,
        ..Default::default()
    };
    let market = ReferenceMarket::new(&cfg, cfg.seed);
    let requests = build_requests(&cfg, &market, cfg.seed + 2);
    assert_eq!(requests.len(), 606);
    assert_eq!(requests_fingerprint(&requests), 0xe38f_c6d6_ea1f_d0a4);
    let first = requests[0];
    assert_eq!(
        (
            first.step,
            first.entity,
            first.wallet,
            first.size,
            first.direction,
            first.informed,
            first.signal,
        ),
        (7, 1, 4, 27, 1, false, 0)
    );
    let last = requests[requests.len() - 1];
    assert_eq!(
        (
            last.step,
            last.entity,
            last.wallet,
            last.size,
            last.direction,
            last.informed,
            last.signal,
        ),
        (3_999, 7, 21, 128, 1, true, -1)
    );
    // A wallet belongs to exactly one entity, which is the structure the
    // per-entity cap depends on.
    for r in &requests {
        assert_eq!(r.wallet / cfg.wallets_per_entity, r.entity);
    }
}

#[test]
fn a_quote_is_the_same_quote() {
    let cfg = SimConfig {
        steps: 4_000,
        ..Default::default()
    };
    let makers = build_market_makers(&cfg, cfg.seed + 1);
    assert_eq!(makers[0].half_spread(0.3, 100), 23);
    assert_eq!(makers[0].quote(100_000, 100, 0.3), (100_123, 99_877));
}

#[test]
fn python_rounds_half_to_even_and_so_does_this() {
    // Rust's own round() would give 1, 2, 3, 4 here; Python gives 0, 2, 2, 4.
    assert_eq!(
        [py_round(0.5), py_round(1.5), py_round(2.5), py_round(3.5)],
        [0, 2, 2, 4]
    );
}

/// The whole arm, not just its parts. These figures come from running
/// `qomm_sim.engine.run_arm` on the same configuration; if the port drifts, one
/// of them moves.
#[test]
fn a_whole_arm_reproduces_the_python_run() {
    use qomm_sim::disclosure::{Disclosure, DpDisclosure};
    use qomm_sim::engine::{run_arm, ArmOptions};

    let cfg = SimConfig {
        steps: 4_000,
        window_steps: 200,
        ..Default::default()
    };
    let market = ReferenceMarket::new(&cfg, cfg.seed);
    let makers = build_market_makers(&cfg, cfg.seed + 1);
    let requests = build_requests(&cfg, &market, cfg.seed + 2);

    let expected = [
        // protocol, disclosure, aggregates, observations, all per-entity
        // window fields, and every release field.
        (
            "plain_rfq",
            "A",
            477u64,
            388u64,
            124_348.0f64,
            865usize,
            0x9b9f_7837_5dd6_04ba,
            0xb72b_0a56_0eec_c1a9,
        ),
        (
            "qomm_rfq",
            "A",
            477,
            388,
            124_348.0,
            0,
            0x9b9f_7837_5dd6_04ba,
            0xb72b_0a56_0eec_c1a9,
        ),
        // Re-taken after the two differential-privacy corrections: fills are
        // clipped per entity rather than against the request sum, and every
        // enrolled entity is charged every window rather than only the active
        // ones. Both move which windows publish, so they move the arm. The
        // `A` rows above are untouched, which is what says this is the
        // correction and not a divergence: current CPython gives
        // (477, 388, 124348, 865) and (474, 400, 116143, 874) for these four.
        (
            "plain_rfq",
            "C",
            474,
            400,
            116_143.0,
            874,
            0xf1b5_99a3_1fd3_dbbf,
            0x3161_d798_72e2_96e9,
        ),
        (
            "qomm_rfq",
            "C",
            474,
            400,
            116_143.0,
            0,
            0xf1b5_99a3_1fd3_dbbf,
            0x3161_d798_72e2_96e9,
        ),
    ];
    for (protocol, mode, fills, rejected, pnl, observations, entity_fields, release_fields) in
        expected
    {
        let mut disclosure = if mode == "A" {
            Disclosure::None
        } else {
            Disclosure::Dp(Box::new(DpDisclosure::new(
                1.0,
                3,
                300,
                cfg.n_entities,
                40.0,
                true,
            )))
        };
        let mut options = ArmOptions::new(protocol, 99);
        options.reactive = true;
        let r = run_arm(&cfg, &market, &requests, &makers, &mut disclosure, &options);
        assert_eq!(
            (r.fills, r.rejected),
            (fills, rejected),
            "{protocol} {mode}"
        );
        assert_eq!(r.mm_pnl_total(), pnl, "{protocol} {mode}");
        assert_eq!(r.observations.len(), observations, "{protocol} {mode}");
        assert_eq!(
            entity_fields_fingerprint(&r.windows),
            entity_fields,
            "per-entity window fields for {protocol} {mode}"
        );
        assert_eq!(
            releases_fingerprint(&r.releases),
            release_fields,
            "release fields for {protocol} {mode}"
        );
        // The query-oblivious arms leave no observation channel at all, which is
        // the property every detection result rests on.
        if protocol.starts_with("qomm") {
            assert!(r.observations.is_empty());
        }
    }
}

/// Hiding the request does not change what the market does: the two arms fill
/// the same trades at the same prices. Only who saw the request differs.
#[test]
fn hiding_the_request_changes_the_observations_and_nothing_else() {
    use qomm_sim::disclosure::Disclosure;
    use qomm_sim::engine::{run_arm, ArmOptions};

    let cfg = SimConfig {
        steps: 4_000,
        window_steps: 200,
        ..Default::default()
    };
    let market = ReferenceMarket::new(&cfg, cfg.seed);
    let makers = build_market_makers(&cfg, cfg.seed + 1);
    let requests = build_requests(&cfg, &market, cfg.seed + 2);

    let run = |protocol: &str| {
        let mut disclosure = Disclosure::None;
        run_arm(
            &cfg,
            &market,
            &requests,
            &makers,
            &mut disclosure,
            &ArmOptions::new(protocol, 99),
        )
    };
    let plain = run("plain_rfq");
    let oblivious = run("qomm_rfq");
    assert_eq!(plain.disclosure, oblivious.disclosure);
    assert_eq!(plain.requests, oblivious.requests);
    assert_eq!(plain.fills, oblivious.fills);
    assert_eq!(plain.no_quote, oblivious.no_quote);
    assert_eq!(plain.rejected, oblivious.rejected);
    assert_eq!(plain.user_cost_ticks, oblivious.user_cost_ticks);
    assert_eq!(plain.mm_pnl, oblivious.mm_pnl);
    assert_eq!(plain.mm_markouts, oblivious.mm_markouts);
    assert_eq!(plain.quote_continuation, oblivious.quote_continuation);
    assert_eq!(plain.release_errors, oblivious.release_errors);
    assert_eq!(plain.suppression_rate, oblivious.suppression_rate);
    assert_eq!(plain.epsilon_spent_max, oblivious.epsilon_spent_max);
    assert_eq!(
        format!("{:?}", plain.settlements),
        format!("{:?}", oblivious.settlements)
    );
    assert_eq!(
        format!("{:?}", plain.truth),
        format!("{:?}", oblivious.truth)
    );
    assert_eq!(
        entity_fields_fingerprint(&plain.windows),
        entity_fields_fingerprint(&oblivious.windows)
    );
    assert_eq!(
        format!("{:?}", plain.windows),
        format!("{:?}", oblivious.windows)
    );
    assert_eq!(
        releases_fingerprint(&plain.releases),
        releases_fingerprint(&oblivious.releases)
    );
    assert_eq!(
        format!("{:?}", plain.probe_results),
        format!("{:?}", oblivious.probe_results)
    );
    assert!(!plain.observations.is_empty());
    assert!(oblivious.observations.is_empty());
}
