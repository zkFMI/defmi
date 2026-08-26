use qomm_sim::disclosure::Disclosure;
use qomm_sim::engine::{run_arm, ArmOptions, ArmResult};
use qomm_sim::lab::{self, ArmParams, BuildOptions, LabMarket};
use qomm_sim::market::{
    build_market_makers, build_requests, PricePath, ReferenceMarket, SimConfig,
};

fn setup() -> lab::Setup {
    lab::build(&BuildOptions {
        cfg: SimConfig {
            steps: 4_800,
            window_steps: 120,
            ..SimConfig::default()
        },
        ..BuildOptions::default()
    })
    .unwrap()
}

fn assert_arm_results_equal(left: &ArmResult, right: &ArmResult) {
    assert_eq!(left.protocol, right.protocol);
    assert_eq!(left.disclosure, right.disclosure);
    assert_eq!(left.requests, right.requests);
    assert_eq!(left.fills, right.fills);
    assert_eq!(left.no_quote, right.no_quote);
    assert_eq!(left.rejected, right.rejected);
    assert_eq!(left.user_cost_ticks, right.user_cost_ticks);
    assert_eq!(left.mm_pnl, right.mm_pnl);
    assert_eq!(left.mm_markouts, right.mm_markouts);
    assert_eq!(left.quote_continuation, right.quote_continuation);
    assert_eq!(
        format!("{:?}", left.releases),
        format!("{:?}", right.releases)
    );
    assert_eq!(left.release_errors, right.release_errors);
    assert_eq!(left.suppression_rate, right.suppression_rate);
    assert_eq!(
        format!("{:?}", left.observations),
        format!("{:?}", right.observations)
    );
    assert_eq!(
        format!("{:?}", left.settlements),
        format!("{:?}", right.settlements)
    );
    assert_eq!(format!("{:?}", left.truth), format!("{:?}", right.truth));
    assert_eq!(
        format!("{:?}", left.windows),
        format!("{:?}", right.windows)
    );
    assert_eq!(left.epsilon_spent_max, right.epsilon_spent_max);
    assert_eq!(
        format!("{:?}", left.probe_results),
        format!("{:?}", right.probe_results)
    );
}

#[test]
fn it_builds_the_same_market_the_scripts_build() {
    let setup = setup();
    let market = ReferenceMarket::new(&setup.cfg, setup.cfg.seed);
    let requests = build_requests(&setup.cfg, &market, setup.cfg.seed + 2);
    assert_eq!(setup.requests.len(), requests.len());
    assert_eq!(
        setup
            .requests
            .iter()
            .map(|request| request.step)
            .collect::<Vec<_>>(),
        requests
            .iter()
            .map(|request| request.step)
            .collect::<Vec<_>>()
    );
    assert_eq!(market.mid, setup.market.mid());
}

#[test]
fn one_arm_matches_running_it_directly() {
    let setup = setup();
    let market = ReferenceMarket::new(&setup.cfg, setup.cfg.seed);
    let requests = build_requests(&setup.cfg, &market, setup.cfg.seed + 2);
    let makers = build_market_makers(&setup.cfg, setup.cfg.seed + 1);
    let mut disclosure = Disclosure::None;
    let mut options = ArmOptions::new("plain_rfq", setup.cfg.seed + 5);
    options.probes = setup.probes.clone();
    let direct = run_arm(
        &setup.cfg,
        &market,
        &requests,
        &makers,
        &mut disclosure,
        &options,
    );
    let row = lab::arm(&setup, &ArmParams::default());
    assert_eq!(row.fill_rate, direct.fill_rate());
    assert_eq!(row.mm_pnl_per_fill, direct.mm_pnl_per_fill());
    assert_eq!(row.suppression_rate, None);
    assert_arm_results_equal(&row.result, &direct);
}

/// Every arm must consume the exact market object stored in `Setup`, not merely
/// rebuild an equal-looking market from the same seed.
#[test]
fn arms_share_one_market() {
    let mut setup = setup();
    let LabMarket::Generated(market) = &mut setup.market else {
        panic!("the test setup must use the generated market")
    };
    for (step, mid) in market.mid.iter_mut().enumerate() {
        *mid = 200_000 + (step % 97) as i64;
    }
    let expected_probe_path: Vec<i64> = setup
        .probes
        .iter()
        .map(|probe| setup.market.mid()[probe.step])
        .collect();
    let rows = lab::compare(&setup, &["qomm_rfq", "plain_rfq"], &ArmParams::default());
    for row in &rows {
        assert_eq!(
            row.result
                .probe_results
                .iter()
                .map(|probe| probe.ref_mid)
                .collect::<Vec<_>>(),
            expected_probe_path,
            "{} rebuilt or replaced the setup market",
            row.protocol
        );
    }
    assert_eq!(
        rows[0]
            .result
            .probe_results
            .iter()
            .map(|probe| probe.ref_mid)
            .collect::<Vec<_>>(),
        rows[1]
            .result
            .probe_results
            .iter()
            .map(|probe| probe.ref_mid)
            .collect::<Vec<_>>()
    );
}

#[test]
fn makers_do_not_carry_inventory_between_arms() {
    let setup = setup();
    let first = lab::arm(&setup, &ArmParams::default());
    let second = lab::arm(&setup, &ArmParams::default());
    assert_eq!(first.fill_rate, second.fill_rate);
    assert_eq!(first.mm_pnl_per_fill, second.mm_pnl_per_fill);
}

#[test]
fn the_query_oblivious_arm_is_flat_in_the_adversary() {
    let setup = setup();
    let fixed = ArmParams {
        protocol: "qomm_rfq".to_string(),
        ..ArmParams::default()
    };
    let rows = lab::sweep_rho(&setup, &[0.0, 0.25, 0.5, 1.0], &fixed);
    assert!(rows.iter().all(|row| row.detection_auc == Some(0.5)));
}

#[test]
fn the_plain_arm_rises_with_the_adversary() {
    let setup = setup();
    let rows = lab::sweep_rho(&setup, &[0.0, 0.25, 0.5, 1.0], &ArmParams::default());
    let aucs: Vec<f64> = rows.iter().map(|row| row.detection_auc.unwrap()).collect();
    assert!(aucs.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(aucs[aucs.len() - 1] > aucs[0]);
}

#[test]
fn no_disclosure_reports_no_suppression() {
    let setup = setup();
    assert!(lab::arm(&setup, &ArmParams::default())
        .suppression_rate
        .is_none());
    assert!(lab::arm(
        &setup,
        &ArmParams {
            disclosure: "C_dp".to_string(),
            ..ArmParams::default()
        }
    )
    .suppression_rate
    .is_some());
}

#[test]
fn sweeping_epsilon_keeps_the_other_knobs_still() {
    let setup = setup();
    let fixed = ArmParams {
        disclosure: "C_dp".to_string(),
        reactive: true,
        rho: 0.75,
        debias: false,
        signed_sensitivity_factor: 2.0,
        ..ArmParams::default()
    };
    let rows = lab::sweep_epsilon(&setup, &[0.25, 1.0, 4.0], &fixed);
    assert_eq!(
        rows.iter().map(|row| row.epsilon).collect::<Vec<_>>(),
        vec![0.25, 1.0, 4.0]
    );
    for row in &rows {
        assert_eq!(row.protocol, fixed.protocol);
        assert_eq!(row.disclosure, fixed.disclosure);
        assert_eq!(row.rho, fixed.rho);
        assert_eq!(row.reactive, fixed.reactive);
        assert_eq!(row.result.protocol, fixed.protocol);
        assert_eq!(row.result.disclosure, "C_dp");
        for release in row
            .result
            .releases
            .iter()
            .filter(|release| release.published)
        {
            assert_eq!(release.epsilon_spent, row.epsilon);
            assert!(!release.fields.debiased);
            assert_eq!(
                release.fields.noise_scale_signed / release.fields.noise_scale_requests,
                200.0,
                "signed sensitivity changed at epsilon {}",
                row.epsilon
            );
        }
    }
}

#[test]
fn the_table_renders_missing_values() {
    let setup = setup();
    let text = lab::table(&lab::compare(
        &setup,
        &["qomm_rfq", "plain_rfq"],
        &ArmParams::default(),
    ));
    assert!(text.contains("n/a") && text.contains("qomm_rfq"));
}
