//! What the checker has to establish, stated as tests: a legal rule compiles and
//! carries its own audit; an illegal one is refused with a reason its author can
//! act on; and no rule can read who is asking.

use qomm_dsl::{compile_rule, emit, obligation_plan};
use std::collections::BTreeMap;

const RULE: &str = "\
param mid[99000,101000] half[1,200] slope[0,16] invcoef[0,8]
state inv[-4000,4000]
input qty[1,1000]
ask = mid + half + slope * qty + invcoef * inv
bid = mid - half - slope * qty + invcoef * inv
";

#[test]
fn a_legal_rule_compiles_and_derives_its_own_facts() {
    let rule = compile_rule(RULE, "policy").unwrap();
    assert_eq!(
        rule.secrets(),
        vec!["half", "inv", "invcoef", "mid", "slope"]
    );
    assert_eq!(rule.inputs(), vec!["qty"]);
    // The input is committed with a fresh blinding, so both slope * qty and
    // invcoef * inv are secret-times-secret products in each output.
    assert_eq!(rule.max_degree(), 2);
    let plan = obligation_plan(&rule);
    let products = plan.counts["product"];
    assert_eq!(
        products, 4,
        "one product proof per secret-times-secret term"
    );
    assert!(rule.required_bits() >= 18, "{}", rule.required_bits());
}

#[test]
fn the_width_is_derived_from_the_declared_bounds() {
    let narrow = compile_rule("param a[0,7]\ninput q[0,1]\nout = a + q\n", "n").unwrap();
    let wide = compile_rule("param a[0,1000000]\ninput q[0,1]\nout = a + q\n", "w").unwrap();
    assert!(narrow.required_bits() < wide.required_bits());
}

#[test]
fn a_rule_cannot_read_who_is_asking() {
    for name in ["wallet", "address", "entity", "user_id", "nullifier", "ip"] {
        let source = format!("param a[0,10]\ninput {name}[0,10]\nout = a + {name}\n");
        let err = compile_rule(&source, "bad").unwrap_err();
        assert!(err.0.contains("who is asking"), "{name}: {}", err.0);
    }
}

#[test]
fn the_language_has_no_escape_hatches() {
    for (source, expected) in [
        ("param a[0,10]\ninput q[0,1]\nout = a / q\n", "division"),
        (
            "param a[0,10]\ninput q[0,1]\nout = pow(a, q)\n",
            "may be called",
        ),
        (
            "param a[0,10]\ninput q[0,1]\nout = a + undeclared\n",
            "not declared",
        ),
        ("param a[0,10]\ninput q[0,1]\nout = a < q < 5\n", "chained"),
    ] {
        let err = compile_rule(source, "bad").unwrap_err();
        assert!(err.0.contains(expected), "{source:?} gave {}", err.0);
    }
}

#[test]
fn degree_three_is_refused_because_it_would_cost_a_proof_per_product() {
    let source = "param a[0,10] b[0,10] c[0,10]\ninput q[0,1]\nout = a * b * c + q\n";
    let err = compile_rule(source, "bad").unwrap_err();
    assert!(err.0.contains("degree two"), "{}", err.0);
}

#[test]
fn a_declared_but_unused_parameter_is_refused() {
    let source = "param a[0,10] spare[0,10]\ninput q[0,1]\nout = a + q\n";
    let err = compile_rule(source, "bad").unwrap_err();
    assert!(err.0.contains("never used"), "{}", err.0);
}

#[test]
fn a_declaration_without_a_range_is_refused() {
    let err = compile_rule("param a\ninput q[0,1]\nout = a + q\n", "bad").unwrap_err();
    assert!(err.0.contains("needs a range"), "{}", err.0);
}

#[test]
fn comparisons_and_intrinsics_carry_their_own_obligations() {
    let source = "param cap[0,500] a[0,100]\ninput q[1,1000]\n\
                  fits = q <= cap\nout = min(a, cap) + q\n";
    let rule = compile_rule(source, "gated").unwrap();
    let kinds: Vec<&str> = rule.obligations.iter().map(|o| o.kind.as_str()).collect();
    assert!(kinds.contains(&"range"));
    assert!(
        kinds.contains(&"bit"),
        "a comparison produces a bit to be proved"
    );
    assert!(kinds.contains(&"product"), "min needs a selection product");
    // Every range obligation states the width it needs, so the audit is sized
    // rather than described.
    assert!(rule
        .obligations
        .iter()
        .filter(|o| o.kind == "range")
        .all(|o| o.bits > 0));
}

#[test]
fn the_circuit_and_the_cleartext_evaluator_come_from_the_same_source() {
    let rule = compile_rule(RULE, "policy").unwrap();
    let circuit = emit::to_mpc(&rule);
    assert!(circuit["ask"].contains("col_mid"));
    assert!(circuit["ask"].contains("col_half"));

    let bindings: BTreeMap<String, i128> = [
        ("mid", 100_000),
        ("half", 12),
        ("slope", 3),
        ("invcoef", 2),
        ("inv", -250),
        ("qty", 100),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let values = emit::evaluate(&rule, &bindings).unwrap();
    assert_eq!(values["ask"], 100_000 + 12 + 3 * 100 + 2 * -250);
    assert_eq!(values["bid"], 100_000 - 12 - 3 * 100 + 2 * -250);
}

#[test]
fn clamp_bounds_must_be_constants_so_the_width_stays_static() {
    let bad = "param a[0,100] lo[0,10]\ninput q[1,10]\nout = clamp(a, lo, 50) + q\n";
    assert!(compile_rule(bad, "bad")
        .unwrap_err()
        .0
        .contains("constants"));
    let good = "param a[0,100]\ninput q[1,10]\nout = clamp(a, 5, 50) + q\n";
    let rule = compile_rule(good, "good").unwrap();
    assert_eq!(rule.intervals["out"].lo, 5 + 1);
    assert_eq!(rule.intervals["out"].hi, 50 + 10);
}
