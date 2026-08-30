use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey};
use qomm_proofs::kyb::{cohort_id, present, BusinessAttributes, KybIssuer};
use qomm_transport::mandate::{Direction, MakerPolicyMandate, TakerExecutionMandate, ZERO};
use qomm_transport::pretrade_authority::{
    read_ack_private, read_authority_private, write_ack_private, write_authority_private,
    AcceptanceOpening, MakerPretradeAuthority, PretradeAcknowledgement, PretradeAuthorityBundle,
    PretradeReservationBinding, PretradeSettlementVerifier, ReservationParty,
    TakerPretradeAuthority,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::deal_quorum;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

fn h(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

#[test]
fn private_authority_roundtrip_and_pinned_defmi_ack_bind_both_reservations() {
    let mut issuer = KybIssuer::new(4, &mut OsRng);
    let credential = issuer
        .enroll(
            "legal-entity",
            BusinessAttributes {
                jurisdiction: "JP".into(),
                entity_type: "dealer".into(),
                collateral_tier: 3,
            },
            &mut OsRng,
        )
        .unwrap();
    let cohort = cohort_id("JP", "dealer", 2);
    let registry = issuer.publish(&cohort, 1, 2_000).unwrap();
    let scope = b"qomm/test/pretrade";
    let maker_context = b"maker-context";
    let taker_context = b"taker-context";
    let maker_presentation =
        present(&credential, &registry, scope, maker_context, &mut OsRng).unwrap();
    let taker_presentation =
        present(&credential, &registry, scope, taker_context, &mut OsRng).unwrap();
    let key = Pedersen::new(b"qomm:defmi:v1");
    let maker_blinding = Scalar::random(&mut OsRng);
    let taker_blinding = Scalar::random(&mut OsRng);
    let maker_signer = SigningKey::generate(&mut OsRng);
    let taker_signer = SigningKey::generate(&mut OsRng);
    let maker_handle = RistrettoPoint::mul_base(&Scalar::from(21_u64));
    let taker_handle = RistrettoPoint::mul_base(&Scalar::from(101_u64));
    let venue_id = h("venue");
    let defmi_id = h("defmi");
    let asset_id = h("asset");
    let cash_asset_id = h("cash");
    let (_, frost_public) = deal_quorum(7, 3, &mut OsRng).unwrap();
    let maker = MakerPolicyMandate {
        venue_id,
        defmi_id,
        policy_digest: h("policy"),
        policy_version: 1,
        asset_id: cash_asset_id,
        direction: Direction::TakerSells,
        reserve_id: h("maker-reserve"),
        maximum_amount_commitment: key.commit_u64(70, &maker_blinding).compress().to_bytes(),
        maker_handle: maker_handle.compress().to_bytes(),
        entity_commitment: maker_presentation.entity_commitment(),
        kyb_presentation_digest: maker_presentation.digest(),
        valid_from: 1,
        valid_until: 1_000,
        auto_execute: true,
        maker_public: maker_signer.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0; 64]),
    }
    .sign(&maker_signer)
    .unwrap();
    let taker = TakerExecutionMandate {
        venue_id,
        defmi_id,
        rfq_nullifier: h("rfq"),
        asset_id,
        reserve_asset_id: asset_id,
        direction: Direction::TakerSells,
        quantity_commitment: h("quantity"),
        limit_price_commitment: h("limit"),
        maximum_fee_commitment: h("fee"),
        maximum_amount_commitment: key.commit_u64(50, &taker_blinding).compress().to_bytes(),
        reserve_id: h("taker-reserve"),
        taker_handle: taker_handle.compress().to_bytes(),
        entity_commitment: taker_presentation.entity_commitment(),
        kyb_presentation_digest: taker_presentation.digest(),
        admission_ticket_id: h("ticket"),
        admission_slot: 9,
        deadline: 1_000,
        allow_partial: false,
        auto_settle: true,
        taker_public: taker_signer.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0; 64]),
    }
    .sign(&taker_signer)
    .unwrap();
    let bundle = PretradeAuthorityBundle {
        created_at: 100,
        venue_id,
        defmi_id,
        traded_asset_id: asset_id,
        cash_asset_id,
        identity_scope: scope.to_vec(),
        required_cohort: cohort,
        identity_provider: "test-external-kyb".into(),
        identity_evidence_digest: h("external-identity-evidence"),
        registry,
        admission: None,
        settlement_verifier: PretradeSettlementVerifier {
            epoch: 1,
            quote_registry_digest: h("quote-registry"),
            quote_eligibility_bits: 32,
            quote_span_bits: 32,
            amount_bits: 16,
            price_bits: 32,
            max_horizon: 3_600,
            frost_public,
            valid_from: 1,
            valid_until: 1_000,
        },
        makers: vec![MakerPretradeAuthority {
            maker_index: 0,
            mandate: maker.clone(),
            identity_context: maker_context.to_vec(),
            presentation: maker_presentation,
            acceptance_opening: AcceptanceOpening {
                amount: 70,
                blinding: maker_blinding,
            },
        }],
        takers: vec![TakerPretradeAuthority {
            client_index: 0,
            mandate: taker.clone(),
            identity_context: taker_context.to_vec(),
            presentation: taker_presentation,
            acceptance_opening: AcceptanceOpening {
                amount: 50,
                blinding: taker_blinding,
            },
        }],
    };
    let directory = tempfile::tempdir().unwrap();
    let authority_path = directory.path().join("authority.json");
    write_authority_private(&authority_path, &bundle).unwrap();
    let decoded = read_authority_private(&authority_path).unwrap();
    assert_eq!(decoded.digest().unwrap(), bundle.digest().unwrap());
    decoded.makers[0]
        .mandate
        .verify(
            &decoded.makers[0].presentation,
            &decoded.registry,
            &decoded.registry.issuer,
            &decoded.identity_scope,
            &decoded.makers[0].identity_context,
            &decoded.required_cohort,
            100,
        )
        .unwrap();
    decoded.takers[0]
        .mandate
        .verify(
            &decoded.takers[0].presentation,
            &decoded.registry,
            &decoded.registry.issuer,
            &decoded.identity_scope,
            &decoded.takers[0].identity_context,
            &decoded.required_cohort,
            100,
        )
        .unwrap();

    let receipt_signer = SigningKey::generate(&mut OsRng);
    let acknowledgement = PretradeAcknowledgement {
        authority_digest: decoded.digest().unwrap(),
        defmi_id,
        after_state_root: h("after-root"),
        bindings: vec![
            PretradeReservationBinding {
                party: ReservationParty::Maker,
                owner_index: 0,
                direction: maker.direction,
                owner_handle: maker.maker_handle,
                facility_id: h("maker-facility"),
                reserve_id: maker.reserve_id,
                mandate_digest: maker.digest().unwrap(),
                policy_digest: maker.policy_digest,
                amount_commitment: maker.maximum_amount_commitment,
                reserve_receipt_digest: h("maker-receipt"),
            },
            PretradeReservationBinding {
                party: ReservationParty::Taker,
                owner_index: 0,
                direction: taker.direction,
                owner_handle: taker.taker_handle,
                facility_id: h("taker-facility"),
                reserve_id: taker.reserve_id,
                mandate_digest: taker.digest().unwrap(),
                policy_digest: ZERO,
                amount_commitment: taker.maximum_amount_commitment,
                reserve_receipt_digest: h("taker-receipt"),
            },
        ],
        signer_public: receipt_signer.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0; 64]),
    }
    .sign(&receipt_signer)
    .unwrap();
    let ack_path = directory.path().join("ack.json");
    write_ack_private(&ack_path, &acknowledgement).unwrap();
    let decoded_ack = read_ack_private(&ack_path).unwrap();
    decoded_ack.verify(&receipt_signer.verifying_key()).unwrap();
    assert_eq!(
        decoded_ack.digest().unwrap(),
        acknowledgement.digest().unwrap()
    );
    decoded_ack
        .binding_for(
            ReservationParty::Maker,
            &maker.maker_handle,
            maker.direction,
        )
        .unwrap();

    let wrong = SigningKey::generate(&mut OsRng);
    assert!(decoded_ack.verify(&wrong.verifying_key()).is_err());
}
