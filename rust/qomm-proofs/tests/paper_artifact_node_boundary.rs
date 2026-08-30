//! Keep whole-party aggregation out of the public proof API.

const THRESHOLD_RANGE: &str = include_str!("../src/threshold_range.rs");
const THRESHOLD_GADGETS: &str = include_str!("../src/threshold_gadgets.rs");

#[test]
fn whole_party_aggregate_entry_points_are_not_public() {
    let public_aggregates = [
        (
            "threshold_range",
            THRESHOLD_RANGE,
            "pub fn joint_prove_range<",
        ),
        (
            "threshold_gadgets",
            THRESHOLD_GADGETS,
            "pub fn joint_prove_bit<",
        ),
        (
            "threshold_gadgets",
            THRESHOLD_GADGETS,
            "pub fn joint_prove_product<",
        ),
    ];
    let violations = public_aggregates
        .into_iter()
        .filter(|(_, source, signature)| source.contains(signature))
        .map(|(module, _, signature)| format!("{module}: {signature}"))
        .collect::<Vec<_>>();

    assert!(
        violations.is_empty(),
        "public whole-party aggregate APIs remain:\n{}",
        violations.join("\n")
    );
}
