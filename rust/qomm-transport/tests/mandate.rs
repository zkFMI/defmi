use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey};
use qomm_proofs::kyb::{
    cohort_id, present, BusinessAttributes, KybCredential, KybIssuer, KybPresentation,
    SignedCohortRegistry,
};
use qomm_transport::mandate::{Direction, MakerPolicyMandate, TakerExecutionMandate, ZERO};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

const SCOPE: &[u8] = b"qomm/venue-a/legal-entity";
const CONTEXT: &[u8] = b"venue-a/defmi-a/kyb-v1";

fn h(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct IdentityFixture {
    issuer: KybIssuer,
    registry: SignedCohortRegistry,
    cohort: String,
    maker: KybCredential,
    taker: KybCredential,
}

fn identities() -> IdentityFixture {
    let mut issuer = KybIssuer::new(4, &mut OsRng);
    let attributes = BusinessAttributes {
        jurisdiction: "JP".into(),
        entity_type: "regulated-dealer".into(),
        collateral_tier: 3,
    };
    let maker = issuer
        .enroll("maker-control-group", attributes.clone(), &mut OsRng)
        .unwrap();
    let taker = issuer
        .enroll("taker-control-group", attributes, &mut OsRng)
        .unwrap();
    let cohort = cohort_id("JP", "regulated-dealer", 2);
    let registry = issuer.publish(&cohort, 7, 10_000).unwrap();
    IdentityFixture {
        issuer,
        registry,
        cohort,
        maker,
        taker,
    }
}

fn presentation(credential: &KybCredential, registry: &SignedCohortRegistry) -> KybPresentation {
    present(credential, registry, SCOPE, CONTEXT, &mut OsRng).unwrap()
}

#[test]
fn maker_policy_pre_authorizes_reserve_and_needs_no_quote_time_signature() {
    let identity = identities();
    let proof = presentation(&identity.maker, &identity.registry);
    let key = SigningKey::generate(&mut OsRng);
    let maker_handle = RistrettoPoint::mul_base(&Scalar::from(101u64))
        .compress()
        .to_bytes();
    let mandate = MakerPolicyMandate {
        venue_id: h("venue"),
        defmi_id: h("defmi"),
        policy_digest: h("policy-v4"),
        policy_version: 4,
        asset_id: h("asset"),
        direction: Direction::TakerBuys,
        reserve_id: h("maker-reserve"),
        maximum_amount_commitment: h("maker-max"),
        maker_handle,
        entity_commitment: proof.entity_commitment(),
        kyb_presentation_digest: proof.digest(),
        valid_from: 100,
        valid_until: 900,
        auto_execute: true,
        maker_public: key.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0; 64]),
    }
    .sign(&key)
    .unwrap();
    mandate
        .verify(
            &proof,
            &identity.registry,
            &identity.issuer.public_key(),
            SCOPE,
            CONTEXT,
            &identity.cohort,
            200,
        )
        .unwrap();
    let unsigned = mandate.unsigned().unwrap();
    let decoded =
        MakerPolicyMandate::from_signed_bytes(&unsigned, mandate.signature.to_bytes()).unwrap();
    assert_eq!(decoded.digest().unwrap(), mandate.digest().unwrap());
    let mut trailing = unsigned.clone();
    trailing.push(0);
    assert!(
        MakerPolicyMandate::from_signed_bytes(&trailing, mandate.signature.to_bytes()).is_err()
    );

    let mut changed = mandate.clone();
    changed.reserve_id[0] ^= 1;
    assert!(changed
        .verify(
            &proof,
            &identity.registry,
            &identity.issuer.public_key(),
            SCOPE,
            CONTEXT,
            &identity.cohort,
            200,
        )
        .unwrap_err()
        .contains("signature"));
}

#[test]
fn taker_mandate_binds_rfq_limit_fee_order_and_automatic_settlement() {
    let identity = identities();
    let proof = presentation(&identity.taker, &identity.registry);
    let key = SigningKey::generate(&mut OsRng);
    let taker_handle = RistrettoPoint::mul_base(&Scalar::from(202u64))
        .compress()
        .to_bytes();
    let mandate = TakerExecutionMandate {
        venue_id: h("venue"),
        defmi_id: h("defmi"),
        rfq_nullifier: h("rfq-nullifier"),
        asset_id: h("asset"),
        reserve_asset_id: h("reserve-asset"),
        direction: Direction::TakerSells,
        quantity_commitment: h("quantity"),
        limit_price_commitment: h("limit-price"),
        maximum_fee_commitment: h("maximum-fee"),
        maximum_amount_commitment: h("maximum-amount"),
        reserve_id: h("taker-reserve"),
        taker_handle,
        entity_commitment: proof.entity_commitment(),
        kyb_presentation_digest: proof.digest(),
        admission_ticket_id: h("admission-ticket"),
        admission_slot: 5,
        deadline: 900,
        allow_partial: false,
        auto_settle: true,
        taker_public: key.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0; 64]),
    }
    .sign(&key)
    .unwrap();
    mandate
        .verify(
            &proof,
            &identity.registry,
            &identity.issuer.public_key(),
            SCOPE,
            CONTEXT,
            &identity.cohort,
            200,
        )
        .unwrap();
    let unsigned = mandate.unsigned().unwrap();
    let decoded =
        TakerExecutionMandate::from_signed_bytes(&unsigned, mandate.signature.to_bytes()).unwrap();
    assert_eq!(decoded.digest().unwrap(), mandate.digest().unwrap());
    let mut changed_body = unsigned;
    let changed_index = changed_body.len() - 33;
    changed_body[changed_index] ^= 1;
    assert!(
        TakerExecutionMandate::from_signed_bytes(&changed_body, mandate.signature.to_bytes())
            .is_err()
    );

    let maker_proof = presentation(&identity.maker, &identity.registry);
    assert!(mandate
        .verify(
            &maker_proof,
            &identity.registry,
            &identity.issuer.public_key(),
            SCOPE,
            CONTEXT,
            &identity.cohort,
            200,
        )
        .unwrap_err()
        .contains("another legal entity"));

    let mut no_auto_settle = mandate;
    no_auto_settle.auto_settle = false;
    no_auto_settle.signature = Signature::from_bytes(&[0; 64]);
    assert!(no_auto_settle
        .unsigned()
        .unwrap_err()
        .contains("auto-settle"));
    assert_ne!(no_auto_settle.rfq_nullifier, ZERO);
}
