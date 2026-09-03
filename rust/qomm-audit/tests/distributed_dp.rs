use ed25519_dalek::SigningKey;
use qomm_audit::distributed_dp::{BudgetState, DpMechanism, U64_SPACE};
use qomm_audit::publication::{certify, PublicationCertificate, PublicationStatement, ZERO};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn statement(
    mechanism: &DpMechanism,
    before: u64,
    previous: [u8; 32],
    epoch: u64,
) -> PublicationStatement {
    // The statement carries the privacy delta, not the rounding distance. It
    // used to carry the latter, which is not a privacy parameter and is nine
    // orders of magnitude smaller at support 8.
    let (delta_numerator, delta_denominator) = mechanism.certificate_delta().unwrap();
    PublicationStatement {
        operation_id: Sha256::new()
            .chain_update(b"publication operation")
            .chain_update(epoch.to_be_bytes())
            .finalize()
            .into(),
        budget_scope: Sha256::digest(b"verified legal-entity group").into(),
        venue: "QOMM".into(),
        epoch,
        slot_start: 10,
        slot_end: 19,
        source_digest: Sha256::digest(b"private source rows").into(),
        rule_digest: Sha256::digest(b"entity clipping rule").into(),
        mechanism_digest: mechanism.digest(),
        private_input_commitment: Sha256::digest(b"secret aggregate commitment").into(),
        transcript_digest: Sha256::digest(b"malicious secure MPC transcript").into(),
        output_name: "request_count".into(),
        output_value: 73,
        epsilon_micros: mechanism.epsilon_micros,
        delta_numerator,
        delta_denominator,
        budget_total_micros: 4_000_000,
        budget_before_micros: before,
        budget_after_micros: before + mechanism.epsilon_micros,
        previous_certificate: previous,
    }
}

#[test]
fn cdf_is_complete_monotone_and_samples_stay_in_support() {
    let mechanism = DpMechanism::new(1_000_000, 3, 64).unwrap();
    let thresholds = mechanism.thresholds().unwrap();
    assert_eq!(thresholds.len(), 129);
    assert_eq!(thresholds.last(), Some(&U64_SPACE));
    assert!(thresholds.windows(2).all(|pair| pair[0] < pair[1]));
    for uniform in [0, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
        assert!((-64..=64).contains(&mechanism.sample_u64(uniform).unwrap()));
    }
}

#[test]
fn emitted_program_keeps_exact_value_and_randomness_secret() {
    let mechanism = DpMechanism::new(500_000, 10, 32).unwrap();
    let source = mechanism
        .mp_spdz_source(7, 2_000_000, 500_000, "published")
        .unwrap();
    assert!(source.contains("sint.get_input_from(p)"));
    assert!(source.contains("sint.get_random_bit()"));
    assert_eq!(source.matches(".reveal()").count(), 1);
    assert!(!source.contains("exact.reveal") && !source.contains("u.reveal"));
    assert!(source.contains("published.reveal"));
}

#[test]
fn privacy_budget_exhaustion_blocks_before_generation() {
    let mechanism = DpMechanism::new(750_000, 1, 16).unwrap();
    assert!(mechanism
        .mp_spdz_source(7, 1_000_000, 500_000, "published")
        .unwrap_err()
        .contains("budget"));
    let state = BudgetState {
        total_micros: 1_000_000,
        spent_micros: 0,
    }
    .spend(&mechanism)
    .unwrap();
    assert!(state.spend(&mechanism).unwrap_err().contains("exhausted"));
}

#[test]
fn quorum_certificate_binds_output_budget_source_rule_and_chain() {
    let mechanism = DpMechanism::new(500_000, 3, 32).unwrap();
    let keys = (0..7)
        .map(|index| (format!("node-{index}"), SigningKey::generate(&mut OsRng)))
        .collect::<BTreeMap<_, _>>();
    let registry = keys
        .iter()
        .map(|(node, key)| (node.clone(), key.verifying_key()))
        .collect::<BTreeMap<_, _>>();
    let first_signers = keys
        .iter()
        .take(3)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    let first = certify(statement(&mechanism, 0, ZERO, 1), &first_signers).unwrap();
    assert!(first.verify(&registry, 3, None));
    let second_signers = keys
        .iter()
        .skip(2)
        .take(3)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    let second = certify(
        statement(&mechanism, 500_000, first.digest().unwrap(), 2),
        &second_signers,
    )
    .unwrap();
    assert!(second.verify(&registry, 3, Some(&first)));

    let mut moved = second.statement.clone();
    moved.output_value = 74;
    let forged = PublicationCertificate {
        statement: moved,
        signatures: second.signatures,
    };
    assert!(!forged.verify(&registry, 3, Some(&first)));
}

#[test]
fn two_signers_do_not_meet_three_of_seven() {
    let mechanism = DpMechanism::new(500_000, 3, 32).unwrap();
    let keys = (0..7)
        .map(|index| (format!("node-{index}"), SigningKey::generate(&mut OsRng)))
        .collect::<BTreeMap<_, _>>();
    let registry = keys
        .iter()
        .map(|(node, key)| (node.clone(), key.verifying_key()))
        .collect::<BTreeMap<_, _>>();
    let signers = keys
        .iter()
        .take(2)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    let certificate = certify(statement(&mechanism, 0, ZERO, 1), &signers).unwrap();
    assert!(!certificate.verify(&registry, 3, None));
}

/// The bound `rounding_delta` returns has to hold against the distance computed
/// without floating point. The value this replaces --- `(2s+1)/2^64` --- did
/// not: it bounded the flooring of the endpoints and ignored that the CDF they
/// are floored from is accumulated in `f64`, whose resolution near one is
/// `2^-53`. Nothing checked it, because the only test that touched
/// `rounding_delta` put it in a statement and compared statements.
#[test]
fn rounding_delta_is_a_bound_and_the_old_one_was_not() {
    for (epsilon_micros, sensitivity, support) in [
        (1_000_000_u64, 1_u64, 8_u16),
        (1_000_000, 1, 16),
        (1_000_000, 1, 32),
        (500_000, 3, 24),
        (250_000, 1, 64),
    ] {
        let mechanism = DpMechanism::new(epsilon_micros, sensitivity, support).unwrap();
        let distance = exact_rounding_distance(&mechanism);
        let (numerator, denominator) = mechanism.rounding_delta();
        let bound = numerator as f64 / denominator as f64;
        assert!(
            distance <= bound,
            "support {support}: distance {distance:e} exceeds the bound {bound:e}"
        );
        let old_bound = (2.0 * (2.0 * f64::from(support) + 1.0)) / 2f64.powi(64);
        assert!(
            distance > old_bound,
            "support {support}: the old bound {old_bound:e} would have held against \
             {distance:e}, so this test cannot show it was wrong"
        );
    }
}

/// The `delta` a certificate carries has to be the one truncation actually
/// costs. Two closed forms were used for it before this test existed and both
/// understate it: the folded tail by `e^epsilon`, and the endpoint cell by
/// however many cells the sensitivity shifts past.
#[test]
fn privacy_delta_beats_the_closed_forms_that_were_used_for_it() {
    for (epsilon_micros, sensitivity, support) in [
        (1_000_000_u64, 1_u64, 8_u16),
        (1_000_000, 1, 16),
        (1_000_000, 1, 32),
        (500_000, 3, 24),
        (750_000, 2, 20),
    ] {
        let mechanism = DpMechanism::new(epsilon_micros, sensitivity, support).unwrap();
        let delta = mechanism.privacy_delta().unwrap();
        let epsilon = epsilon_micros as f64 / 1e6;
        let alpha = (-epsilon / sensitivity as f64).exp();
        let normalizer = (1.0 - alpha) / (1.0 + alpha);
        let endpoint = normalizer * alpha.powi(i32::from(support)) / (1.0 - alpha);
        let folded_tail = normalizer * alpha.powi(i32::from(support) + 1) / (1.0 - alpha);
        assert!(
            delta >= endpoint * (1.0 - 1e-9),
            "eps={epsilon} sens={sensitivity} support={support}: delta {delta:e} \
             is below the endpoint cell {endpoint:e}"
        );
        assert!(
            delta > folded_tail,
            "eps={epsilon} sens={sensitivity} support={support}: delta {delta:e} \
             is not above the folded tail {folded_tail:e}"
        );
        if sensitivity > 1 {
            assert!(
                delta > endpoint * 1.2,
                "eps={epsilon} sens={sensitivity} support={support}: at sensitivity \
                 above one the endpoint cell {endpoint:e} should understate \
                 delta {delta:e}"
            );
        }
    }
}

/// The margin between what truncation costs and what rounding costs is not
/// uniform, and prose that flattens it is wrong at one end or the other.
#[test]
fn truncation_leads_rounding_by_a_margin_that_collapses_with_support() {
    let orders = |support: u16| {
        let mechanism = DpMechanism::new(1_000_000, 1, support).unwrap();
        let alpha = (-1.0_f64).exp();
        let normalizer = (1.0 - alpha) / (1.0 + alpha);
        let truncation = 2.0 * normalizer * alpha.powi(i32::from(support) + 1) / (1.0 - alpha);
        truncation / exact_rounding_distance(&mechanism)
    };
    assert!(
        (orders(8).log10() - 11.9).abs() < 0.2,
        "support 8: {}",
        orders(8).log10()
    );
    assert!(
        (orders(16).log10() - 8.2).abs() < 0.2,
        "support 16: {}",
        orders(16).log10()
    );
    assert!(
        (orders(32) - 10.1).abs() < 1.0,
        "support 32: {}",
        orders(32)
    );
}

/// Total variation between the cells the mechanism releases and the exact
/// truncated law, with the exact law summed in a way that does not reuse the
/// implementation's own accumulation.
fn exact_rounding_distance(mechanism: &DpMechanism) -> f64 {
    let epsilon = mechanism.epsilon_micros as f64 / 1_000_000.0;
    let alpha = (-epsilon / mechanism.sensitivity as f64).exp();
    let normalizer = (1.0 - alpha) / (1.0 + alpha);
    let support = i32::from(mechanism.support);
    let mut intended = vec![normalizer * alpha.powi(support) / (1.0 - alpha)];
    for value in (-support + 1)..support {
        intended.push(normalizer * alpha.powi(value.abs()));
    }
    intended.push(normalizer * alpha.powi(support) / (1.0 - alpha));
    let released = mechanism.released_cells().unwrap();
    released
        .iter()
        .zip(intended.iter())
        .map(|(had, want)| (had - want).abs())
        .sum::<f64>()
        / 2.0
}

/// A certificate has to bind the privacy `delta`, and the rounding distance is
/// not one. At support 8 the two differ by ten orders of magnitude, in the
/// direction that flatters the release.
#[test]
fn a_certificate_binds_the_privacy_delta_and_not_the_rounding_distance() {
    let mechanism = DpMechanism::new(1_000_000, 1, 8).unwrap();
    let (numerator, denominator) = mechanism.certificate_delta().unwrap();
    let carried = numerator as f64 / denominator as f64;
    let delta = mechanism.privacy_delta().unwrap();
    assert!(
        carried >= delta,
        "certificate {carried:e} is below the delta {delta:e}"
    );
    assert!(
        carried < delta * 1.000_001,
        "certificate {carried:e} is not tight"
    );
    let (rounding_numerator, rounding_denominator) = mechanism.rounding_delta();
    let rounding = rounding_numerator as f64 / rounding_denominator as f64;
    assert!(
        carried > rounding * 1e8,
        "the rounding distance {rounding:e} is close enough to the delta \
         {carried:e} that this test cannot show they were confused"
    );
}

/// `privacy_delta` has to be a delta for every mechanism the type admits, not
/// only for the handful a hand-written table covers. Two invariants hold
/// regardless of the parameters and neither needs a reference implementation:
/// when the sensitivity shifts the support clear of itself nothing overlaps and
/// the delta is exactly one, and a delta is always in `[0, 1]`.
///
/// The version this replaces returned **zero** at `epsilon = 709.782713` with
/// sensitivity 710 and support 8, where the true delta is one, because
/// `e^epsilon` overflows to infinity there and `infinity * 0.0` is NaN, which
/// `f64::max` resolves to its other operand.
#[test]
fn privacy_delta_is_a_delta_across_the_whole_parameter_space() {
    let mut checked = 0;
    for epsilon_micros in [
        1_u64,
        1_000,
        500_000,
        1_000_000,
        50_000_000,
        200_000_000,
        709_000_000,
        709_782_712,
        709_782_713,
        1_000_000_000,
        u64::MAX / 4,
    ] {
        for sensitivity in [1_u64, 2, 3, 7, 64, 710, 4096] {
            for support in [1_u16, 8, 16, 32, 256] {
                let Ok(mechanism) = DpMechanism::new(epsilon_micros, sensitivity, support) else {
                    continue;
                };
                let Ok(delta) = mechanism.privacy_delta() else {
                    continue;
                };
                checked += 1;
                assert!(
                    delta.is_finite() && (0.0..=1.0 + 1e-12).contains(&delta),
                    "eps_micros={epsilon_micros} sens={sensitivity} support={support}: \
                     delta {delta} is not a probability"
                );
                if sensitivity > 2 * u64::from(support) {
                    assert!(
                        delta > 1.0 - 1e-9,
                        "eps_micros={epsilon_micros} sens={sensitivity} support={support}: \
                         the sensitivity clears the support, so nothing overlaps and delta \
                         must be one, not {delta}"
                    );
                }
                match mechanism.certificate_delta() {
                    Ok((numerator, denominator)) => {
                        let carried = numerator as f64 / denominator as f64;
                        assert!(
                            carried >= delta,
                            "eps_micros={epsilon_micros} sens={sensitivity} \
                             support={support}: the certificate carries {carried} \
                             below the delta {delta}"
                        );
                    }
                    Err(reason) => assert!(
                        delta > 0.9 && reason.contains("no guarantee to certify"),
                        "eps_micros={epsilon_micros} sens={sensitivity} support={support}: \
                         refused with delta {delta}: {reason}"
                    ),
                }
            }
        }
    }
    assert!(checked > 100, "only {checked} mechanisms were reachable");
}

/// A statement carrying the rounding distance where its privacy delta belongs
/// passes `validate`, because a proper fraction is all `validate` can see. That
/// is how one came to be built and signed. `validate_against` is the check that
/// catches it.
#[test]
fn a_statement_carrying_the_rounding_distance_is_rejected_against_its_mechanism() {
    let mechanism = DpMechanism::new(1_000_000, 1, 8).unwrap();
    let honest = statement(&mechanism, 0, [0_u8; 32], 1);
    assert!(honest.validate().is_ok());
    assert!(honest.validate_against(&mechanism).is_ok());

    let (numerator, denominator) = mechanism.rounding_delta();
    let mut understated = honest.clone();
    understated.delta_numerator = numerator;
    understated.delta_denominator = denominator;
    assert!(
        understated.validate().is_ok(),
        "validate alone cannot see the difference, which is the point"
    );
    let error = understated
        .validate_against(&mechanism)
        .expect_err("the rounding distance is not a privacy delta");
    assert!(error.contains("below the mechanism"), "{error}");

    let mut wrong_mechanism = honest.clone();
    wrong_mechanism.epsilon_micros = 2_000_000;
    wrong_mechanism.budget_after_micros = wrong_mechanism.budget_before_micros + 2_000_000;
    assert!(wrong_mechanism.validate_against(&mechanism).is_err());
}
