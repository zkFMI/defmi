use ed25519_dalek::SigningKey;
use qomm_proofs::kyb::{cohort_id, present, verify_presentation, BusinessAttributes, KybIssuer};
use qomm_transport::kyb_wire::{KybPresentationWire, KybRegistryWire};
use rand_core::OsRng;

#[test]
fn signed_registry_and_anonymous_presentation_round_trip_canonically() {
    let mut issuer = KybIssuer::with_signing_key(4, SigningKey::generate(&mut OsRng)).unwrap();
    let credential = issuer
        .enroll(
            "legal-entity-a",
            BusinessAttributes {
                jurisdiction: "JP".into(),
                entity_type: "regulated-dealer".into(),
                collateral_tier: 3,
            },
            &mut OsRng,
        )
        .unwrap();
    let cohort = cohort_id("JP", "regulated-dealer", 2);
    let registry = issuer.publish(&cohort, 9, 10_000).unwrap();
    let scope = b"venue-a";
    let context = b"defmi-a/participant-service";
    let presentation = present(&credential, &registry, scope, context, &mut OsRng).unwrap();

    let registry_wire = KybRegistryWire::from_registry(&registry);
    let presentation_wire = KybPresentationWire::from_presentation(&presentation);
    let registry_round_trip = registry_wire.clone().into_registry().unwrap();
    let presentation_round_trip = presentation_wire.clone().into_presentation().unwrap();
    verify_presentation(
        &presentation_round_trip,
        &registry_round_trip,
        &issuer.public_key(),
        scope,
        context,
        100,
        &cohort,
    )
    .unwrap();
    assert_eq!(presentation_round_trip.digest(), presentation.digest());
    assert_eq!(
        serde_json::to_value(registry_wire).unwrap(),
        serde_json::to_value(KybRegistryWire::from_registry(&registry_round_trip)).unwrap()
    );
    assert_eq!(
        serde_json::to_value(presentation_wire).unwrap(),
        serde_json::to_value(KybPresentationWire::from_presentation(
            &presentation_round_trip
        ))
        .unwrap()
    );
}

#[test]
fn noncanonical_scalar_is_rejected() {
    let mut issuer = KybIssuer::new(4, &mut OsRng);
    let credential = issuer
        .enroll(
            "legal-entity-b",
            BusinessAttributes {
                jurisdiction: "JP".into(),
                entity_type: "regulated-dealer".into(),
                collateral_tier: 3,
            },
            &mut OsRng,
        )
        .unwrap();
    let cohort = cohort_id("JP", "regulated-dealer", 2);
    let registry = issuer.publish(&cohort, 1, 10_000).unwrap();
    let presentation = present(&credential, &registry, b"scope", b"context", &mut OsRng).unwrap();
    let mut wire = KybPresentationWire::from_presentation(&presentation);
    wire.responses[0] = "ff".repeat(32);
    assert!(wire.into_presentation().unwrap_err().contains("canonical"));
}
