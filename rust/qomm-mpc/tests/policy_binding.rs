use qomm_dsl::compile_rule;
use qomm_dsl::emit::evaluate;
use qomm_dsl::registry::embedded_policy_rule_digest;
use qomm_mpc::program::{
    build_program, policy_rule_digest, policy_rule_source, ProgramConfig, Reference,
    POLICY_RULE_NAME,
};
use std::collections::BTreeMap;

#[test]
fn generated_mpc_carries_the_digest_of_the_exact_checked_policy() {
    for reference in [Reference::Anchored, Reference::None] {
        for price_conditionals in 0..=4 {
            let config = ProgramConfig {
                reference,
                price_conditionals,
                ..ProgramConfig::default()
            };
            let source = build_program(&config).unwrap();
            assert_eq!(
                embedded_policy_rule_digest(&source).unwrap(),
                policy_rule_digest(&config).unwrap()
            );
            assert_eq!(
                source
                    .lines()
                    .filter(|line| line.contains("QOMM_POLICY_RULE_DIGEST="))
                    .count(),
                1
            );
        }
    }
}

#[test]
fn the_checked_policy_evaluates_the_product_price_formula() {
    let config = ProgramConfig::default();
    let rule = compile_rule(&policy_rule_source(&config), POLICY_RULE_NAME).unwrap();
    let bindings = BTreeMap::from([
        ("ask_level".into(), 50_i128),
        ("spread".into(), 12),
        ("slope".into(), 3),
        ("invcoef".into(), 2),
        ("use_ref".into(), 1),
        ("inv".into(), -250),
        ("qty".into(), 100),
        ("ref_price".into(), 100_000),
    ]);
    let values = evaluate(&rule, &bindings).unwrap();
    let anchored = 50 + 100_000;
    let depth = 3 * 100;
    let skew = 2 * -250;
    assert_eq!(values["anchored"], anchored);
    assert_eq!(values["depth"], depth);
    assert_eq!(values["skew"], skew);
    assert_eq!(values["ask"], anchored + depth + skew);
    assert_eq!(values["bid"], anchored - 12 - depth + skew);
}

#[test]
fn reference_and_conditional_changes_change_the_rule_identity() {
    let anchored = ProgramConfig::default();
    let no_reference = ProgramConfig {
        reference: Reference::None,
        ..anchored.clone()
    };
    let clamped = ProgramConfig {
        price_conditionals: 2,
        ..anchored.clone()
    };
    assert_ne!(
        policy_rule_digest(&anchored).unwrap(),
        policy_rule_digest(&no_reference).unwrap()
    );
    assert_ne!(
        policy_rule_digest(&anchored).unwrap(),
        policy_rule_digest(&clamped).unwrap()
    );
}
