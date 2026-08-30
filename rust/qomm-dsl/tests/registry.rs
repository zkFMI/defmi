//! The registry's whole job is to make one substitution detectable and another
//! one not: swapping a secret parameter must keep the digest, swapping the rule
//! or the emitted program must not.

use qomm_dsl::compile_rule;
use qomm_dsl::registry::{
    program_digest, rule_digest, CircuitRegistry, RuleRegistry, POLICY_RULE_DIGEST_MARKER,
};

const RULE: &str = "\
param mid[99000,101000] half[1,200] slope[0,16]
input qty[1,1000]
ask = mid + half + slope * qty
";

fn marked_program(rule_source: &str, body: &str) -> String {
    let rule = compile_rule(rule_source, "policy").unwrap();
    format!("{POLICY_RULE_DIGEST_MARKER}{}\n{body}", rule_digest(&rule))
}

#[test]
fn the_digest_covers_the_form_and_not_the_values() {
    // The bands are the form. A maker choosing a different half-spread inside
    // the same band produces the same rule and so the same digest.
    let a = compile_rule(RULE, "policy").unwrap();
    let b = compile_rule(RULE, "policy").unwrap();
    assert_eq!(rule_digest(&a), rule_digest(&b));

    // Widening a band changes the form, and so the digest.
    let widened = RULE.replace("half[1,200]", "half[1,400]");
    let c = compile_rule(&widened, "policy").unwrap();
    assert_ne!(rule_digest(&a), rule_digest(&c));
}

#[test]
fn the_rule_digest_ignores_comments_and_spacing() {
    let approved = compile_rule(RULE, "policy").unwrap();
    let formatted = compile_rule(&format!("# a note\n\n{RULE}"), "policy").unwrap();
    assert_eq!(rule_digest(&approved), rule_digest(&formatted));
}

#[test]
fn the_approved_rule_records_the_required_width() {
    let mut registry = RuleRegistry::default();
    let approved = registry.approve(RULE, "policy").unwrap();
    assert_eq!(
        approved.required_bits,
        compile_rule(RULE, "policy").unwrap().required_bits()
    );
}

#[test]
fn a_substituted_rule_is_rejected_against_the_approved_digest() {
    let mut registry = RuleRegistry::default();
    let approved = registry.approve(RULE, "policy").unwrap();
    assert_eq!(registry.check(RULE, "policy", &approved.digest), Ok(()));

    let other = RULE.replace("mid + half", "mid + half + half");
    assert!(registry.check(&other, "policy", &approved.digest).is_err());
}

#[test]
fn a_digest_that_was_never_approved_is_rejected_before_anything_is_compiled() {
    let registry = RuleRegistry::default();
    assert_eq!(
        registry.check(RULE, "policy", &"0".repeat(64)),
        Err("the claimed digest is not an approved rule form")
    );
}

#[test]
fn the_program_digest_ignores_formatting_and_nothing_else() {
    let program = "a = 1\nb = 2\n";
    assert_eq!(
        program_digest(program),
        program_digest("a = 1  \nb = 2\n\n")
    );
    assert_ne!(program_digest(program), program_digest("a = 1\nb = 3\n"));
}

#[test]
fn a_circuit_is_approved_for_one_shape_and_not_another() {
    let mut registry = CircuitRegistry::default();
    let program = marked_program(RULE, "col_ask = col_mid + col_half\n");
    registry
        .approve("policy", RULE, &program, &[16, 31])
        .unwrap();

    assert_eq!(registry.check(&program, &[16, 31]), Ok(()));
    assert!(registry
        .check(&program, &[32, 31])
        .unwrap_err()
        .contains("no circuit is approved"));
    let substituted = marked_program(RULE, "col_ask = col_mid\n");
    assert!(registry
        .check(&substituted, &[16, 31])
        .unwrap_err()
        .contains("does not match what was approved"));
}

#[test]
fn approving_a_rule_does_not_approve_running_a_different_program() {
    // This is the gap the second digest exists to close: a node holding the
    // approved rule digest could still hand its compiler something else.
    let mut registry = CircuitRegistry::default();
    let approved = marked_program(RULE, "col_ask = col_mid + col_half\n");
    registry
        .approve("policy", RULE, &approved, &[16, 31])
        .unwrap();
    let substituted = marked_program(
        RULE,
        "col_ask = col_mid + col_half + col_slope * col_slope\n",
    );
    assert!(registry.check(&substituted, &[16, 31]).is_err());
}

#[test]
fn a_program_marked_with_another_rule_cannot_be_approved() {
    let other = RULE.replace("slope * qty", "slope * qty + half");
    let source = marked_program(&other, "col_ask = col_mid + col_half\n");
    let error = CircuitRegistry::default()
        .approve("policy", RULE, &source, &[16, 31])
        .unwrap_err();
    assert!(error.0.contains("different price-rule DSL"), "{}", error.0);
}
