//! The two properties that make this worth having: a presentation says nothing
//! about which entity made it, and every wallet of one entity still lands on
//! the same counter.

use curve25519_dalek::scalar::Scalar;
use qomm_proofs::kyb::{
    cohort_id, present, verify_presentation, verify_registry, BusinessAttributes, EntityLimits,
    EntityRateLimiter, Invalid, KybIssuer, Refused,
};
use rand_core::OsRng;

const SCOPE: &[u8] = b"venue/quotes/2026-08";
const CTX: &[u8] = b"slot=41";

fn issuer_with(n: u32) -> (KybIssuer, Vec<qomm_proofs::kyb::KybCredential>) {
    let mut issuer = KybIssuer::new(5, &mut OsRng);
    let credentials = (0..n)
        .map(|i| {
            issuer
                .enroll(
                    &format!("group-{i}"),
                    BusinessAttributes {
                        jurisdiction: "JP".into(),
                        entity_type: "bank".into(),
                        collateral_tier: 3,
                    },
                    &mut OsRng,
                )
                .unwrap()
        })
        .collect();
    (issuer, credentials)
}

#[test]
fn a_member_presents_and_a_non_member_cannot() {
    let (mut issuer, credentials) = issuer_with(4);
    let cohort = cohort_id("JP", "bank", 2);
    let registry = issuer.publish(&cohort, 1, 10_000).unwrap();
    let key = issuer.public_key();

    let presentation = present(&credentials[2], &registry, SCOPE, CTX, &mut OsRng).unwrap();
    assert_eq!(
        verify_presentation(&presentation, &registry, &key, SCOPE, CTX, 1, &cohort),
        Ok(())
    );

    // An entity enrolled after the registry was published is not in it.
    let outsider = issuer
        .enroll(
            "late",
            BusinessAttributes {
                jurisdiction: "JP".into(),
                entity_type: "bank".into(),
                collateral_tier: 3,
            },
            &mut OsRng,
        )
        .unwrap();
    assert!(present(&outsider, &registry, SCOPE, CTX, &mut OsRng).is_err());
}

#[test]
fn a_tier_gate_is_membership_and_costs_the_prover_nothing() {
    let mut issuer = KybIssuer::new(5, &mut OsRng);
    let low = issuer
        .enroll(
            "low",
            BusinessAttributes {
                jurisdiction: "JP".into(),
                entity_type: "bank".into(),
                collateral_tier: 1,
            },
            &mut OsRng,
        )
        .unwrap();
    let high = issuer
        .enroll(
            "high",
            BusinessAttributes {
                jurisdiction: "JP".into(),
                entity_type: "bank".into(),
                collateral_tier: 4,
            },
            &mut OsRng,
        )
        .unwrap();
    assert_eq!(low.cohorts.len(), 1);
    assert_eq!(high.cohorts.len(), 4);

    let tier3 = cohort_id("JP", "bank", 3);
    let registry = issuer.publish(&tier3, 1, 10_000).unwrap();
    assert_eq!(registry.points.len(), 1, "only the tier-4 entity qualifies");
    assert!(present(&low, &registry, SCOPE, CTX, &mut OsRng).is_err());
    assert!(present(&high, &registry, SCOPE, CTX, &mut OsRng).is_ok());
}

#[test]
fn the_nullifier_is_the_same_across_wallets_and_different_across_scopes() {
    let (_, credentials) = issuer_with(2);
    let entity = &credentials[0];
    // "Two wallets" is two presentations by the same credential; the counter
    // must not be able to tell them apart.
    assert_eq!(entity.scope_nullifier(SCOPE), entity.scope_nullifier(SCOPE));
    assert_ne!(
        entity.scope_nullifier(SCOPE),
        entity.scope_nullifier(b"other/scope")
    );
    assert_ne!(
        entity.scope_nullifier(SCOPE),
        credentials[1].scope_nullifier(SCOPE)
    );
}

#[test]
fn rerandomized_proofs_share_one_durable_scope_binding() {
    let (issuer, credentials) = issuer_with(3);
    let cohort = cohort_id("JP", "bank", 2);
    let registry = issuer.publish(&cohort, 1, 10_000).unwrap();
    let first = present(&credentials[0], &registry, SCOPE, CTX, &mut OsRng).unwrap();
    let second = present(&credentials[0], &registry, SCOPE, CTX, &mut OsRng).unwrap();

    assert_ne!(
        first.digest(),
        second.digest(),
        "fresh membership proofs must not reuse a transcript"
    );
    assert_eq!(
        first.binding_digest(),
        second.binding_digest(),
        "one legal entity must not gain another reserve by presenting again"
    );

    let other_scope = present(
        &credentials[0],
        &registry,
        b"another/venue",
        CTX,
        &mut OsRng,
    )
    .unwrap();
    assert_ne!(first.binding_digest(), other_scope.binding_digest());
}

#[test]
fn a_presentation_does_not_carry_to_another_scope_or_context() {
    let (issuer, credentials) = issuer_with(4);
    let cohort = cohort_id("JP", "bank", 2);
    let registry = issuer.publish(&cohort, 1, 10_000).unwrap();
    let key = issuer.public_key();
    let presentation = present(&credentials[1], &registry, SCOPE, CTX, &mut OsRng).unwrap();

    assert_eq!(
        verify_presentation(&presentation, &registry, &key, b"other", CTX, 1, &cohort),
        Err(Invalid::WrongScopeOrContext)
    );
    assert_eq!(
        verify_presentation(
            &presentation,
            &registry,
            &key,
            SCOPE,
            b"slot=42",
            1,
            &cohort
        ),
        Err(Invalid::WrongScopeOrContext)
    );
}

#[test]
fn an_expired_or_untrusted_registry_is_refused() {
    let (issuer, _) = issuer_with(3);
    let cohort = cohort_id("JP", "bank", 2);
    let registry = issuer.publish(&cohort, 1, 100).unwrap();
    assert_eq!(
        verify_registry(&registry, &issuer.public_key(), 100),
        Err(Invalid::Expired)
    );

    let other = KybIssuer::new(5, &mut OsRng);
    assert_eq!(
        verify_registry(&registry, &other.public_key(), 1),
        Err(Invalid::NotFromTrustedIssuer)
    );
}

#[test]
fn a_tampered_registry_fails_its_own_id() {
    let (issuer, _) = issuer_with(3);
    let cohort = cohort_id("JP", "bank", 2);
    let mut registry = issuer.publish(&cohort, 1, 10_000).unwrap();
    registry
        .points
        .push(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut OsRng));
    assert_eq!(
        verify_registry(&registry, &issuer.public_key(), 1),
        Err(Invalid::RegistryIdMismatch)
    );
}

#[test]
fn the_limit_counts_the_entity_and_not_the_wallet() {
    let (_, credentials) = issuer_with(2);
    let mut limiter = EntityRateLimiter::new(EntityLimits {
        max_requests: 3,
        max_probe_lots: 100,
        max_epsilon: 1.0,
    });
    let entity = credentials[0].scope_nullifier(SCOPE);

    for _ in 0..3 {
        assert_eq!(limiter.allow_request(&entity, 7, 10), Ok(()));
    }
    // A fourth request from any wallet of the same entity is refused.
    assert_eq!(
        limiter.allow_request(&entity, 7, 10),
        Err(Refused::RequestCap)
    );
    // A different epoch starts fresh, and a different entity is unaffected.
    assert_eq!(limiter.allow_request(&entity, 8, 10), Ok(()));
    assert_eq!(
        limiter.allow_request(&credentials[1].scope_nullifier(SCOPE), 7, 10),
        Ok(())
    );
    assert_eq!(limiter.usage(&entity, 7).requests, 3);
}

#[test]
fn probing_volume_and_the_privacy_budget_are_capped_separately() {
    let (_, credentials) = issuer_with(1);
    let mut limiter = EntityRateLimiter::new(EntityLimits {
        max_requests: 100,
        max_probe_lots: 50,
        max_epsilon: 0.5,
    });
    let entity = credentials[0].scope_nullifier(SCOPE);

    assert_eq!(limiter.allow_request(&entity, 1, 40), Ok(()));
    assert_eq!(
        limiter.allow_request(&entity, 1, 20),
        Err(Refused::ProbeVolumeCap)
    );
    assert_eq!(limiter.spend_epsilon(&entity, 1, 0.4), Ok(()));
    assert_eq!(
        limiter.spend_epsilon(&entity, 1, 0.2),
        Err(Refused::PrivacyBudget)
    );
}
