use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey};
use qomm_transport::mandate::{Direction, TakerExecutionMandate};
use qomm_transport::mpc_result::fill_mask_scalar_commitment;
use qomm_transport::rfq_frame::{
    ResidentRfqCatalogBinding, ResidentRfqInput, ResidentRfqOpenings, RESIDENT_RFQ_FIELDS,
};
use qomm_transport::wire::reconstruct;
use qomm_zk::Pedersen;
use sha2::{Digest, Sha256};

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn high_scalar(tag: u8) -> Scalar {
    let mut wide = [0_u8; 64];
    wide[20] = tag;
    wide[47] = tag.wrapping_add(1);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn fixture(
    direction: Direction,
) -> (
    TakerExecutionMandate,
    ResidentRfqCatalogBinding,
    ResidentRfqOpenings,
) {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let quantity = 25;
    let quantity_blinding = high_scalar(3);
    let executable_limit = if direction == Direction::TakerBuys {
        15_000
    } else {
        10_000
    };
    let limit_blinding = high_scalar(5);
    let reserve_amount = if direction == Direction::TakerBuys {
        500_000
    } else {
        25
    };
    let reserve_blinding = high_scalar(7);
    let signing = SigningKey::from_bytes(&digest("rfq-frame-taker-key"));
    let traded_asset_id = digest("rfq-frame-security");
    let cash_asset_id = digest("rfq-frame-cash");
    let fill_mask = high_scalar(13);
    let mandate = TakerExecutionMandate {
        venue_id: digest("rfq-frame-venue"),
        defmi_id: digest("rfq-frame-defmi"),
        rfq_nullifier: digest("rfq-frame-nullifier"),
        asset_id: traded_asset_id,
        reserve_asset_id: if direction == Direction::TakerBuys {
            cash_asset_id
        } else {
            traded_asset_id
        },
        direction,
        quantity_commitment: key
            .commit_u64(quantity, &quantity_blinding)
            .compress()
            .to_bytes(),
        limit_price_commitment: key
            .commit_u64(executable_limit, &limit_blinding)
            .compress()
            .to_bytes(),
        maximum_fee_commitment: key
            .commit_u64(1_000, &Scalar::from(9_u64))
            .compress()
            .to_bytes(),
        maximum_amount_commitment: key
            .commit_u64(reserve_amount, &reserve_blinding)
            .compress()
            .to_bytes(),
        reserve_id: digest("rfq-frame-reserve"),
        taker_handle: RistrettoPoint::mul_base(&Scalar::from(12_u64))
            .compress()
            .to_bytes(),
        entity_commitment: digest("rfq-frame-entity"),
        kyb_presentation_digest: digest("rfq-frame-kyb"),
        admission_ticket_id: digest("rfq-frame-ticket"),
        admission_slot: 11,
        fill_mask_commitment: fill_mask_scalar_commitment(fill_mask.to_bytes()),
        deadline: 100,
        allow_partial: false,
        auto_settle: true,
        taker_public: signing.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0_u8; 64]),
    }
    .sign(&signing)
    .unwrap();
    (
        mandate,
        ResidentRfqCatalogBinding {
            asset_index: 2,
            asset_count: 4,
            traded_asset_id,
            cash_asset_id,
            entity_slot: 41,
        },
        ResidentRfqOpenings {
            quantity,
            quantity_blinding,
            executable_limit,
            limit_blinding,
            reserve_amount,
            reserve_blinding,
            response_mask: high_scalar(11),
            fill_mask,
        },
    )
}

#[test]
fn signed_buy_uses_only_the_dynamic_cash_reserve_and_preserves_full_scalars() {
    let (mandate, catalog, openings) = fixture(Direction::TakerBuys);
    let input = ResidentRfqInput::from_signed_mandate(&mandate, &catalog, &openings, 11, 99)
        .expect("valid signed RFQ");
    let payloads = input.share(7).unwrap();
    let values = reconstruct(&payloads, RESIDENT_RFQ_FIELDS).unwrap();
    assert_eq!(values.as_slice(), input.values());
    assert_eq!(values[2].as_u128(), Some(0));
    assert_eq!(values[10].as_u128(), Some(0));
    assert_eq!(values[11].as_u128(), Some(0));
    assert_eq!(
        values[12].as_u128(),
        Some(u128::from(openings.reserve_amount))
    );
    assert!(values[13].as_u128().is_none(), "full scalar was narrowed");
}

#[test]
fn signed_sell_uses_only_the_dynamic_securities_reserve() {
    let (mandate, catalog, openings) = fixture(Direction::TakerSells);
    let input = ResidentRfqInput::from_signed_mandate(&mandate, &catalog, &openings, 11, 99)
        .expect("valid signed RFQ");
    let values = input.values();
    assert_eq!(values[2].as_u128(), Some(1));
    assert_eq!(
        values[10].as_u128(),
        Some(u128::from(openings.reserve_amount))
    );
    assert!(values[11].as_u128().is_none());
    assert_eq!(values[12].as_u128(), Some(0));
    assert_eq!(values[13].as_u128(), Some(0));
}

#[test]
fn a_changed_opening_slot_or_asset_is_rejected_before_sharing() {
    let (mandate, mut catalog, mut openings) = fixture(Direction::TakerBuys);
    openings.reserve_amount += 1;
    assert!(
        ResidentRfqInput::from_signed_mandate(&mandate, &catalog, &openings, 11, 99)
            .unwrap_err()
            .contains("openings")
    );
    openings.reserve_amount -= 1;
    assert!(
        ResidentRfqInput::from_signed_mandate(&mandate, &catalog, &openings, 12, 99)
            .unwrap_err()
            .contains("slot")
    );
    catalog.cash_asset_id = digest("wrong-cash");
    assert!(
        ResidentRfqInput::from_signed_mandate(&mandate, &catalog, &openings, 11, 99)
            .unwrap_err()
            .contains("rail")
    );
}

#[test]
fn cover_has_no_query_but_keeps_both_opened_response_masks_secret() {
    let input = ResidentRfqInput::cover(&mut rand_core::OsRng);
    let values = input.values();
    for (index, value) in values.iter().enumerate() {
        if index != 5 && index != 8 {
            assert_eq!(*value, qomm_transport::wire::FieldElement::ZERO);
        }
    }
    assert_ne!(values[5], qomm_transport::wire::FieldElement::ZERO);
    assert_ne!(values[8], qomm_transport::wire::FieldElement::ZERO);
}
