use qomm_proofs::kyb::{cohort_id, present, verify_presentation, BusinessAttributes, Invalid};
use qomm_transport::kyb_lifecycle::KybLifecycleService;
use qomm_transport::node_service::KybPolicy;
use rand_core::OsRng;

const SCOPE: &[u8] = b"QOMM/venue-A/KYB";
const CONTEXT: &[u8] = b"mutual-TLS-client-fingerprint";

fn attributes() -> BusinessAttributes {
    BusinessAttributes {
        jurisdiction: "JP".into(),
        entity_type: "regulated-dealer".into(),
        collateral_tier: 3,
    }
}

#[test]
fn issuance_revocation_appeal_merge_cache_and_restart_form_one_lifecycle() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("kyb-lifecycle.qks");
    let passphrase = b"node-local-kyb-lifecycle-passphrase";
    let signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let issuer = signing.verifying_key();
    let service = KybLifecycleService::open(&path, passphrase, signing.clone(), 5).unwrap();
    let first = service
        .issue("group-a", b"LEI-A", attributes(), 100, &mut OsRng)
        .unwrap();
    let second = service
        .issue("group-b", b"LEI-B", attributes(), 101, &mut OsRng)
        .unwrap();
    let cohort = cohort_id("JP", "regulated-dealer", 2);
    let registry1 = service
        .publish_registry(&cohort, 1, u64::MAX - 1, 102)
        .unwrap();
    let old_first = present(&first, &registry1, SCOPE, CONTEXT, &mut OsRng).unwrap();
    let old_second = present(&second, &registry1, SCOPE, CONTEXT, &mut OsRng).unwrap();
    let policy = KybPolicy::new(SCOPE.to_vec(), &cohort, registry1.clone(), issuer).unwrap();

    service
        .revoke("group-a", b"registry mismatch", 103)
        .unwrap();
    let case = service
        .open_appeal("group-a", b"corrected official filing", 104)
        .unwrap();
    let registry2 = service
        .publish_registry(&cohort, 2, u64::MAX - 1, 105)
        .unwrap();
    policy.update_registry(registry2.clone()).unwrap();
    assert_eq!(policy.registry_epoch().unwrap(), 2);
    assert_eq!(
        verify_presentation(&old_first, &registry2, &issuer, SCOPE, CONTEXT, 106, &cohort,),
        Err(Invalid::WrongRegistryEpoch)
    );
    assert!(present(&first, &registry2, SCOPE, CONTEXT, &mut OsRng).is_err());
    assert!(policy
        .update_registry(registry1)
        .unwrap_err()
        .contains("stale"));

    let reinstated = service
        .resolve_appeal(case, true, 107, &mut OsRng)
        .unwrap()
        .unwrap();
    let registry3 = service
        .publish_registry(&cohort, 3, u64::MAX - 1, 108)
        .unwrap();
    policy.update_registry(registry3.clone()).unwrap();
    let reinstated_presentation =
        present(&reinstated, &registry3, SCOPE, CONTEXT, &mut OsRng).unwrap();
    assert_eq!(
        verify_presentation(
            &reinstated_presentation,
            &registry3,
            &issuer,
            SCOPE,
            CONTEXT,
            109,
            &cohort,
        ),
        Ok(())
    );

    // Merging two control groups rotates the canonical credential and removes
    // both old points. All wallets in the combined group receive the one new
    // credential, so Sybil wallets do not retain two entity budgets.
    let merged = service
        .merge("group-a", "group-b", 110, &mut OsRng)
        .unwrap();
    let registry4 = service
        .publish_registry(&cohort, 4, u64::MAX - 1, 111)
        .unwrap();
    policy.update_registry(registry4.clone()).unwrap();
    assert!(present(&second, &registry4, SCOPE, CONTEXT, &mut OsRng).is_err());
    assert_eq!(
        verify_presentation(
            &old_second,
            &registry4,
            &issuer,
            SCOPE,
            CONTEXT,
            112,
            &cohort,
        ),
        Err(Invalid::WrongRegistryEpoch)
    );
    let merged_presentation = present(&merged, &registry4, SCOPE, CONTEXT, &mut OsRng).unwrap();
    assert_eq!(
        verify_presentation(
            &merged_presentation,
            &registry4,
            &issuer,
            SCOPE,
            CONTEXT,
            112,
            &cohort,
        ),
        Ok(())
    );

    let events = service.audit_event_count().unwrap();
    drop(service);
    let reopened = KybLifecycleService::open(&path, passphrase, signing, 5).unwrap();
    assert_eq!(reopened.audit_event_count().unwrap(), events);
    assert_eq!(
        reopened
            .latest_registry(&cohort, 113)
            .unwrap()
            .unwrap()
            .registry_id,
        registry4.registry_id
    );
    assert!(KybLifecycleService::open(
        &path,
        b"wrong-node-local-passphrase",
        ed25519_dalek::SigningKey::generate(&mut OsRng),
        5,
    )
    .is_err());
}
