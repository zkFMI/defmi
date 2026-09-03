//! A rule's audit is a compiler output, so the test is that it holds for a rule
//! nobody wrote proofs for by hand — and that it fails when any part is moved.

use qomm_dsl::compile_rule;
use qomm_proofs::rule_audit::{RuleProver, RuleVerifier, Step};
use rand_core::OsRng;
use std::collections::BTreeMap;

const RULE: &str = "\
param ask_level[99000,101000] spread[2,400] slope[0,16] invcoef[0,8]
state inv[-4000,4000]
input qty[1,1000]
ask = ask_level + slope * qty + invcoef * inv
bid = ask_level - spread - slope * qty + invcoef * inv
";

const GATED: &str = "\
param cap[1,1000] base[1,200]
input qty[1,1000]
fits = qty <= cap
price = base + min(qty, cap)
";

fn bindings(pairs: &[(&str, i128)]) -> BTreeMap<String, i128> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn honest() -> BTreeMap<String, i128> {
    bindings(&[
        ("ask_level", 100_012),
        ("spread", 24),
        ("slope", 3),
        ("invcoef", 2),
        ("inv", -250),
        ("qty", 100),
    ])
}

#[test]
fn an_honest_rule_audits_and_the_value_is_the_one_it_computes() {
    let rule = compile_rule(RULE, "policy").unwrap();
    let (prover, verifier) = (RuleProver::new(), RuleVerifier::new());
    let audit = prover.prove(&rule, &honest(), b"ctx", &mut OsRng).unwrap();
    assert_eq!(verifier.verify(&rule, &audit, b"ctx"), Ok(()));
    assert_eq!(audit.output_values["ask"], 100_012 + 3 * 100 + 2 * -250);
    assert_eq!(
        audit.output_values["bid"],
        100_012 - 24 - 3 * 100 + 2 * -250
    );
}

#[test]
fn the_audit_is_sized_by_the_rule_and_not_by_hand() {
    let rule = compile_rule(RULE, "policy").unwrap();
    let audit = RuleProver::new()
        .prove(&rule, &honest(), b"ctx", &mut OsRng)
        .unwrap();
    let size = audit.size();
    // Four secret-times-secret products in the source, four product steps here.
    assert_eq!(size["product"], 4);
    // Five secrets share one aggregated declared-range proof.
    assert_eq!(
        size["declared_range"], 8,
        "aggregation pads to a power of two"
    );
}

#[test]
fn a_value_outside_its_declared_band_cannot_be_proved() {
    let rule = compile_rule(RULE, "policy").unwrap();
    let mut over = honest();
    over.insert("spread".into(), 1_000); // band is [2, 400]
    let err = RuleProver::new()
        .prove(&rule, &over, b"ctx", &mut OsRng)
        .unwrap_err();
    assert!(err.0.contains("outside its declared range"), "{}", err.0);
}

#[test]
fn an_audit_does_not_carry_to_another_context() {
    let rule = compile_rule(RULE, "policy").unwrap();
    let audit = RuleProver::new()
        .prove(&rule, &honest(), b"ctx", &mut OsRng)
        .unwrap();
    assert!(RuleVerifier::new()
        .verify(&rule, &audit, b"another")
        .is_err());
}

#[test]
fn moving_a_committed_value_breaks_the_step_that_used_it() {
    let rule = compile_rule(RULE, "policy").unwrap();
    let mut audit = RuleProver::new()
        .prove(&rule, &honest(), b"ctx", &mut OsRng)
        .unwrap();
    let key = RuleProver::new().key;
    for step in audit.steps.iter_mut() {
        if let Step::Product { c, .. } = step {
            **c += key.g;
            break;
        }
    }
    assert!(RuleVerifier::new().verify(&rule, &audit, b"ctx").is_err());
}

#[test]
fn a_declared_commitment_swapped_for_another_is_caught() {
    let rule = compile_rule(RULE, "policy").unwrap();
    let mut audit = RuleProver::new()
        .prove(&rule, &honest(), b"ctx", &mut OsRng)
        .unwrap();
    let spread = audit.declared["spread"];
    audit.declared.insert("slope".into(), spread);
    assert!(RuleVerifier::new().verify(&rule, &audit, b"ctx").is_err());
}

#[test]
fn comparisons_and_intrinsics_audit_too() {
    let rule = compile_rule(GATED, "gated").unwrap();
    let values = bindings(&[("cap", 400), ("base", 10), ("qty", 100)]);
    let audit = RuleProver::new()
        .prove(&rule, &values, b"ctx", &mut OsRng)
        .unwrap();
    assert_eq!(RuleVerifier::new().verify(&rule, &audit, b"ctx"), Ok(()));
    assert_eq!(audit.output_values["fits"], 1);
    assert_eq!(audit.output_values["price"], 10 + 100);
    let size = audit.size();
    assert!(
        size["range"] >= 3,
        "the comparison and min both need range steps"
    );
    assert!(size["bit"] >= 1);
}

#[test]
fn a_comparison_that_does_not_hold_cannot_be_proved() {
    let rule = compile_rule(GATED, "gated").unwrap();
    // qty above cap makes `qty <= cap` false, and a false comparison has no
    // non-negative difference to prove.
    let values = bindings(&[("cap", 50), ("base", 10), ("qty", 900)]);
    let err = RuleProver::new()
        .prove(&rule, &values, b"ctx", &mut OsRng)
        .unwrap_err();
    assert!(err.0.contains("non-negative"), "{}", err.0);
}
