use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey};
use qomm_defmi::facility::{
    build_threshold_dvp_consumption, build_threshold_dvp_consumption_from_snapshot,
    reserve_handle_for, AccountOpening, AdmissionBatchPlan, AdmissionCommitteePlan,
    AdmissionSlotAdvance, AssetDefinition, AssetKind, CreditAmendmentMode, CreditControlAction,
    CreditFacilityAmendment, CreditFacilityAmendmentProof, CreditFacilityControl,
    CreditFacilityGrant, CreditFacilityRelationProof, CreditFacilityStatus,
    CreditFacilityTransition, CreditHoldSnapshot, CreditTransitionKind, DefmiFacility,
    GuarantorDefinition, GuarantorKind, ProductReleaseOrder, ProductSettlementBatch,
    ProductSettlementBatchMember, ProductSettlementOrder, QuorumApproval, QuorumAuthorizer,
    ReservationAuthorization, ReservationConsumption, ReservationEscrow, ReservationRole,
    SettlementOrder, StateLeg, ZERO,
};
use qomm_defmi::ledger::Ledger;
use qomm_defmi::product::{
    escrow_transfer_context, release_reservation, reserve_maker, reserve_taker,
    settle_product_threshold as settle_product_threshold_authorized, IdentityEvidence,
    ReservationEscrowProof,
};
use qomm_defmi::settlement::{
    account_of, build_threshold_package_from_proofs, Sides, CASH_RAIL, SECURITIES_RAIL,
};
use qomm_proofs::kyb::{cohort_id, present, BusinessAttributes, KybIssuer, SignedCohortRegistry};
use qomm_proofs::price_limit::{prove as prove_price_limit, PriceLimitDirection};
use qomm_proofs::threshold_gadgets::LocalProductShares;
use qomm_proofs::threshold_range::{
    deal_bits, joint_prove_range_from_contributions, LocalRangeShares,
};
use qomm_proofs::threshold_sigma::deal;
use qomm_transport::dvp_issuer::{
    assemble_proofs as assemble_dvp_proofs, make_challenge as make_dvp_challenge,
    relation_statements_from_evaluations as dvp_relation_statements,
    statements_from_evaluations as dvp_statements, MpcDvpNode,
};
use qomm_transport::mandate::{Direction, MakerPolicyMandate, TakerExecutionMandate};
use qomm_transport::order::{verify_admission_lane, NodeAdmissionAttestation, OrderedAdmission};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::typed::{
    digest_for as typed_digest_for, AuthorizationScope, ExecutionContext, OperationKind,
    TradeDirection, TypedInstruction,
};
use qomm_zkpi::{
    asset_scalar, deal_quorum, frost, typed_wire, Bounds, Issuer, Openings, PartialInstruction,
    Venue, AMOUNT_RANGE_CONTEXT, DEFAULT_DOMAIN, PRICE_RANGE_CONTEXT,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

fn h(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn synthetic_product_order(label: &str, admission_sequence: u64) -> ProductSettlementOrder {
    let value = |name: &str| h(&format!("synthetic-product-{label}-{name}"));
    let traded_asset_id = value("security");
    let payment_asset_id = value("cash");
    let typed_instruction_digest = value("typed-instruction");
    let quote_proof_digest = value("quote-proof");
    let settlement = SettlementOrder {
        operation_id: value("settlement-operation"),
        nullifier: value("payment-nullifier"),
        deadline: 10_000,
        payment_instruction_digest: typed_instruction_digest,
        proof_digest: quote_proof_digest,
        market_statement_digest: value("market-statement"),
        legs: vec![
            StateLeg {
                handle: value("security-source"),
                asset_id: traded_asset_id,
                before_commitment: value("security-source-before"),
                after_commitment: value("security-source-after"),
                before_sequence: 0,
            },
            StateLeg {
                handle: value("security-destination"),
                asset_id: traded_asset_id,
                before_commitment: value("security-destination-before"),
                after_commitment: value("security-destination-after"),
                before_sequence: 0,
            },
            StateLeg {
                handle: value("cash-source"),
                asset_id: payment_asset_id,
                before_commitment: value("cash-source-before"),
                after_commitment: value("cash-source-after"),
                before_sequence: 0,
            },
            StateLeg {
                handle: value("cash-destination"),
                asset_id: payment_asset_id,
                before_commitment: value("cash-destination-before"),
                after_commitment: value("cash-destination-after"),
                before_sequence: 0,
            },
        ],
    };
    let settlement_digest = settlement.statement().unwrap();
    let quantity_commitment = value("quantity");
    let cash_commitment = value("cash-amount");
    let transition = |role: &str, consumed_commitment| CreditFacilityTransition {
        operation_id: value(&format!("{role}-consume-operation")),
        facility_id: value(&format!("{role}-facility")),
        hold_id: value(&format!("{role}-hold")),
        kind: CreditTransitionKind::Consume,
        query_commitment: value(&format!("{role}-query")),
        amount_commitment: value(&format!("{role}-amount")),
        consumed_commitment,
        refund_commitment: value(&format!("{role}-refund")),
        before_available_commitment: value(&format!("{role}-available-before")),
        after_available_commitment: value(&format!("{role}-available-after")),
        before_held_commitment: value(&format!("{role}-held-before")),
        after_held_commitment: value(&format!("{role}-held-after")),
        before_outstanding_commitment: value(&format!("{role}-outstanding-before")),
        after_outstanding_commitment: value(&format!("{role}-outstanding-after")),
        before_sequence: 1,
        expires_at: 9_000,
        settlement_digest,
        relation_proof_digest: value(&format!("{role}-relation-proof")),
    };
    ProductSettlementOrder {
        settlement,
        venue_id: h("synthetic-product-venue"),
        defmi_id: h("synthetic-product-defmi"),
        maker_entity_commitment: value("maker-entity"),
        taker_entity_commitment: value("taker-entity"),
        rfq_nullifier: value("rfq-nullifier"),
        taker_authorization_digest: value("taker-authorization"),
        maker_policy_digest: value("maker-policy"),
        maker_mandate_digest: value("maker-mandate"),
        taker_mandate_digest: value("taker-mandate"),
        typed_instruction_digest,
        quote_proof_digest,
        price_limit_proof_digest: value("price-limit-proof"),
        dvp_proof_digest: value("dvp-proof"),
        quantity_commitment,
        cash_commitment,
        traded_asset_id,
        asset_link_proof_digest: value("asset-link-proof"),
        admission_receipt_digest: value("admission-receipt"),
        admission_epoch: 1,
        admission_sequence,
        reservations: vec![
            ReservationConsumption {
                role: ReservationRole::Maker,
                reserve_receipt_digest: value("maker-reserve-receipt"),
                transition: transition("maker", quantity_commitment),
            },
            ReservationConsumption {
                role: ReservationRole::Taker,
                reserve_receipt_digest: value("taker-reserve-receipt"),
                transition: transition("taker", cash_commitment),
            },
        ],
    }
}

fn rebind_product_settlement(order: &mut ProductSettlementOrder) {
    let statement = order.settlement.statement().unwrap();
    for reservation in &mut order.reservations {
        reservation.transition.settlement_digest = statement;
    }
}

#[test]
fn product_batch_statement_matches_the_avalanche_consensus_domain() {
    let batch = ProductSettlementBatch {
        batch_id: h("cross-batch"),
        venue_id: h("cross-venue"),
        defmi_id: h("cross-defmi"),
        admission_epoch: 9,
        members: vec![
            ProductSettlementBatchMember {
                admission_sequence: 3,
                settlement_statement: h("cross-settlement-a"),
            },
            ProductSettlementBatchMember {
                admission_sequence: 7,
                settlement_statement: h("cross-settlement-b"),
            },
        ],
    };
    assert_eq!(
        hex::encode(batch.statement().unwrap()),
        "74489d866a07a01d97c0dd04dc85c2616476ef33921591eacdea6657c1e285c6"
    );
    let mut reordered = batch;
    reordered.members.swap(0, 1);
    assert!(reordered
        .statement()
        .unwrap_err()
        .contains("admission ordered"));
}

#[test]
fn product_batch_rejects_every_cross_order_double_spend_surface() {
    let first = synthetic_product_order("first", 1);
    let second = synthetic_product_order("second", 2);
    ProductSettlementBatch::from_orders(
        h("disjoint-product-batch"),
        &[first.clone(), second.clone()],
    )
    .expect("fully disjoint simultaneous RFQs");

    let mut collision = second.clone();
    collision.reservations[0].transition.facility_id = first.reservations[0].transition.facility_id;
    assert!(ProductSettlementBatch::from_orders(
        h("facility-collision"),
        &[first.clone(), collision]
    )
    .unwrap_err()
    .contains("credit facility"));

    let mut collision = second.clone();
    collision.reservations[0].transition.hold_id = first.reservations[0].transition.hold_id;
    assert!(
        ProductSettlementBatch::from_orders(h("hold-collision"), &[first.clone(), collision])
            .unwrap_err()
            .contains("reservation hold")
    );

    let mut collision = second.clone();
    collision.settlement.legs[0].handle = first.settlement.legs[0].handle;
    rebind_product_settlement(&mut collision);
    let error =
        ProductSettlementBatch::from_orders(h("account-collision"), &[first.clone(), collision])
            .unwrap_err();
    assert!(error.contains("account"), "unexpected rejection: {error}");

    let mut collision = second.clone();
    collision.settlement.nullifier = first.settlement.nullifier;
    rebind_product_settlement(&mut collision);
    assert!(ProductSettlementBatch::from_orders(
        h("payment-collision"),
        &[first.clone(), collision]
    )
    .unwrap_err()
    .contains("payment nullifier"));

    let mut collision = second;
    collision.rfq_nullifier = first.rfq_nullifier;
    assert!(
        ProductSettlementBatch::from_orders(h("rfq-collision"), &[first, collision])
            .unwrap_err()
            .contains("RFQ nullifier")
    );
}

fn keys() -> BTreeMap<String, SigningKey> {
    (0..7)
        .map(|index| (format!("node-{index}"), SigningKey::generate(&mut OsRng)))
        .collect()
}

fn authorizer(keys: &BTreeMap<String, SigningKey>) -> QuorumAuthorizer {
    QuorumAuthorizer::new(
        keys.iter()
            .map(|(node, key)| (node.clone(), key.verifying_key()))
            .collect(),
        3,
        1,
        "defmi:local",
    )
    .unwrap()
}

fn approve(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    statement: [u8; 32],
    count: usize,
) -> QuorumApproval {
    let signers = keys
        .iter()
        .take(count)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    authorizer
        .approve(statement, facility.state_root().unwrap(), &signers)
        .unwrap()
}

/// One admitted population: the lanes (claims and tickets in lane order)
/// a certified committee attests to for one venue, epoch, slot and order.
struct AdmissionPopulation<'a> {
    label: &'a str,
    venue_id: [u8; 32],
    epoch: u64,
    slot: u64,
    first_sequence: u64,
    claims: &'a [[u8; 32]],
    tickets: &'a [[u8; 32]],
    order_digest: [u8; 32],
}

fn certified_admission_population(
    population: AdmissionPopulation<'_>,
) -> (
    AdmissionCommitteePlan,
    AdmissionBatchPlan,
    Vec<Vec<NodeAdmissionAttestation>>,
) {
    let AdmissionPopulation {
        label,
        venue_id,
        epoch,
        slot,
        first_sequence,
        claims,
        tickets,
        order_digest,
    } = population;
    assert_eq!(claims.len(), tickets.len());
    let node_keys = (0..7)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect::<Vec<_>>();
    let node_batches = (0..7)
        .map(|node| h(&format!("{label}:node-batch:{node}")))
        .collect::<Vec<_>>();
    let lanes = claims
        .iter()
        .zip(tickets)
        .enumerate()
        .map(|(lane, (claim, ticket))| {
            node_keys
                .iter()
                .enumerate()
                .map(|(node, key)| {
                    NodeAdmissionAttestation {
                        node: node as u16,
                        slot,
                        sequence: first_sequence + lane as u64,
                        principal_digest: h(&format!("{label}:principal:{lane}")),
                        ticket_id: *ticket,
                        claim_digest: *claim,
                        batch_digest: node_batches[node],
                        order_digest,
                        signature: Signature::from_bytes(&[0; 64]),
                    }
                    .sign(key)
                    .unwrap()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let verifying = node_keys
        .iter()
        .map(SigningKey::verifying_key)
        .collect::<Vec<_>>();
    let certified = lanes
        .iter()
        .map(|lane| verify_admission_lane(lane, &verifying).unwrap())
        .collect::<Vec<_>>();
    let batch_digest = certified[0].cluster_digest;
    let committee = AdmissionCommitteePlan {
        operation_id: h(&format!("{label}:committee-operation")),
        venue_id,
        epoch,
        node_keys: verifying.iter().map(|key| key.to_bytes()).collect(),
        valid_from: 1,
        valid_until: 2_000,
    };
    let plan = AdmissionBatchPlan {
        operation_id: h(&format!("{label}:batch-operation")),
        batch_id: h(&format!("{label}:batch-id")),
        venue_id,
        epoch,
        slot,
        batch_digest,
        order_digest,
        first_sequence: certified[0].sequence,
        admission_digests: certified
            .iter()
            .map(|lane| lane.digest(venue_id, epoch).unwrap())
            .collect(),
        expires_at: 1_000,
    };
    (committee, plan, lanes)
}

fn register(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    label: &str,
    kind: AssetKind,
    decimals: u8,
) -> AssetDefinition {
    let asset = AssetDefinition {
        asset_id: h(&format!("asset:{label}")),
        code: label.into(),
        kind,
        decimals,
        terms_digest: h(&format!("terms:{label}")),
    };
    facility
        .register_asset(
            &asset,
            &approve(facility, authorizer, keys, asset.statement().unwrap(), 3),
        )
        .unwrap();
    asset
}

fn opening(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    label: &str,
    asset: &AssetDefinition,
    commitment: [u8; 32],
) -> AccountOpening {
    let opening = AccountOpening {
        handle: h(&format!("account:{label}")),
        asset_id: asset.asset_id,
        commitment,
        issuance_nonce: h(&format!("issuance:{label}")),
    };
    facility
        .open_account(
            &opening,
            &approve(facility, authorizer, keys, opening.statement().unwrap(), 3),
        )
        .unwrap();
    opening
}

fn opening_with_handle(
    facility: &DefmiFacility,
    authorizer: &QuorumAuthorizer,
    keys: &BTreeMap<String, SigningKey>,
    label: &str,
    handle: [u8; 32],
    asset: &AssetDefinition,
    commitment: [u8; 32],
) -> AccountOpening {
    let opening = AccountOpening {
        handle,
        asset_id: asset.asset_id,
        commitment,
        issuance_nonce: h(&format!("issuance:{label}")),
    };
    facility
        .open_account(
            &opening,
            &approve(facility, authorizer, keys, opening.statement().unwrap(), 3),
        )
        .unwrap();
    opening
}

fn leg(
    account: &AccountOpening,
    asset: &AssetDefinition,
    before: [u8; 32],
    after: [u8; 32],
    sequence: u64,
) -> StateLeg {
    StateLeg {
        handle: account.handle,
        asset_id: asset.asset_id,
        before_commitment: before,
        after_commitment: after,
        before_sequence: sequence,
    }
}

fn order(label: &str, legs: Vec<StateLeg>, deadline: u64) -> SettlementOrder {
    SettlementOrder {
        operation_id: h(&format!("operation:{label}")),
        nullifier: h(&format!("nullifier:{label}")),
        deadline,
        payment_instruction_digest: h(&format!("zkpi:{label}")),
        proof_digest: h(&format!("proof:{label}")),
        market_statement_digest: h(&format!("market:{label}")),
        legs,
    }
}

#[test]
fn consensus_timestamps_fit_sqlites_signed_integer_domain() {
    let max = i64::MAX as u64;
    let overflow = max + 1;
    let state_leg = StateLeg {
        handle: h("timestamp-handle"),
        asset_id: h("timestamp-asset"),
        before_commitment: h("timestamp-before"),
        after_commitment: h("timestamp-after"),
        before_sequence: 0,
    };

    let node_keys = (1_u8..=7)
        .map(|value| {
            SigningKey::from_bytes(&[value; 32])
                .verifying_key()
                .to_bytes()
        })
        .collect::<Vec<_>>();
    let mut committee = AdmissionCommitteePlan {
        operation_id: h("timestamp-committee-operation"),
        venue_id: h("timestamp-committee-venue"),
        epoch: 1,
        node_keys,
        valid_from: 1,
        valid_until: max,
    };
    committee.body().unwrap();
    committee.valid_until = overflow;
    assert!(committee.body().is_err());

    let mut batch = AdmissionBatchPlan {
        operation_id: h("timestamp-batch-operation"),
        batch_id: h("timestamp-batch"),
        venue_id: h("timestamp-batch-venue"),
        epoch: 1,
        slot: 0,
        batch_digest: h("timestamp-batch-digest"),
        order_digest: h("timestamp-order-digest"),
        first_sequence: 1,
        admission_digests: vec![h("timestamp-admission")],
        expires_at: max,
    };
    batch.body().unwrap();
    batch.expires_at = overflow;
    assert!(batch.body().is_err());

    let mut grant = CreditFacilityGrant {
        operation_id: h("timestamp-grant-operation"),
        facility_id: h("timestamp-facility"),
        guarantor_id: h("timestamp-guarantor"),
        beneficiary_commitment: h("timestamp-beneficiary"),
        rail_asset_id: h("timestamp-rail"),
        cap_commitment: h("timestamp-cap"),
        available_commitment: h("timestamp-cap"),
        held_commitment: ZERO,
        outstanding_commitment: ZERO,
        collateral_commitment: h("timestamp-collateral"),
        risk_policy_digest: h("timestamp-policy"),
        relation_proof_digest: h("timestamp-grant-proof"),
        valid_from: 1,
        valid_until: max,
        nonce: h("timestamp-grant-nonce"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    grant.unsigned_body().unwrap();
    grant.valid_until = overflow;
    assert!(grant.unsigned_body().is_err());

    let release_transition = |expires_at| CreditFacilityTransition {
        operation_id: h("timestamp-transition-operation"),
        facility_id: h("timestamp-transition-facility"),
        hold_id: h("timestamp-transition-hold"),
        kind: CreditTransitionKind::Release,
        query_commitment: h("timestamp-query"),
        amount_commitment: h("timestamp-amount"),
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: ZERO,
        after_available_commitment: ZERO,
        before_held_commitment: ZERO,
        after_held_commitment: ZERO,
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: ZERO,
        before_sequence: 0,
        expires_at,
        settlement_digest: ZERO,
        relation_proof_digest: h("timestamp-transition-proof"),
    };
    release_transition(max).body().unwrap();
    assert!(release_transition(overflow).body().is_err());

    let mut amendment = CreditFacilityAmendment {
        operation_id: h("timestamp-amend-operation"),
        facility_id: h("timestamp-amend-facility"),
        mode: CreditAmendmentMode::WithinLimit,
        before_cap_commitment: h("timestamp-amend-before-cap"),
        after_cap_commitment: h("timestamp-amend-after-cap"),
        before_available_commitment: ZERO,
        after_available_commitment: ZERO,
        before_held_commitment: ZERO,
        before_outstanding_commitment: ZERO,
        before_overlimit_commitment: ZERO,
        after_overlimit_commitment: ZERO,
        before_collateral_commitment: h("timestamp-amend-before-collateral"),
        after_collateral_commitment: h("timestamp-amend-after-collateral"),
        before_risk_policy_digest: h("timestamp-amend-before-policy"),
        after_risk_policy_digest: h("timestamp-amend-after-policy"),
        before_valid_until: max,
        after_valid_until: max,
        before_sequence: 0,
        effective_at: max,
        reason_digest: h("timestamp-amend-reason"),
        relation_proof_digest: h("timestamp-amend-proof"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    amendment.unsigned_body().unwrap();
    amendment.effective_at = overflow;
    amendment.after_valid_until = overflow;
    assert!(amendment.unsigned_body().is_err());

    let mut control = CreditFacilityControl {
        operation_id: h("timestamp-control-operation"),
        facility_id: h("timestamp-control-facility"),
        action: CreditControlAction::Freeze,
        before_sequence: 0,
        effective_at: max,
        reason_digest: h("timestamp-control-reason"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    control.unsigned_body().unwrap();
    control.effective_at = overflow;
    assert!(control.unsigned_body().is_err());

    let mut settlement = order("timestamp-settlement", vec![state_leg.clone()], max);
    settlement.body().unwrap();
    settlement.deadline = overflow;
    assert!(settlement.body().is_err());

    let mut product_release = ProductReleaseOrder {
        transition: release_transition(max - 1),
        role: ReservationRole::Maker,
        reserve_receipt_digest: h("timestamp-release-receipt"),
        typed_instruction_digest: h("timestamp-release-instruction"),
        release_nullifier: h("timestamp-release-nullifier"),
        release_deadline: max,
        asset_id: state_leg.asset_id,
        asset_link_proof_digest: h("timestamp-release-asset-proof"),
        refund_leg: state_leg,
    };
    product_release.body().unwrap();
    product_release.release_deadline = overflow;
    assert!(product_release.body().is_err());
}

fn credit_commit(value: u64, blinding: &Scalar) -> [u8; 32] {
    Pedersen::new(b"qomm:defmi:credit-facility:v1")
        .commit_u64(value, blinding)
        .compress()
        .to_bytes()
}

struct CreditFixture {
    _directory: tempfile::TempDir,
    facility: DefmiFacility,
    authorizer: QuorumAuthorizer,
    nodes: BTreeMap<String, SigningKey>,
    guarantor: SigningKey,
    facility_id: [u8; 32],
    cap_blinding: Scalar,
    collateral_blinding: Scalar,
    database_path: PathBuf,
    receipt_key: SigningKey,
}

fn credit_fixture() -> CreditFixture {
    credit_fixture_for(GuarantorKind::Bank)
}

fn credit_fixture_for(kind: GuarantorKind) -> CreditFixture {
    let directory = tempfile::tempdir().unwrap();
    let nodes = keys();
    let authorizer = authorizer(&nodes);
    let database_path = directory.path().join("credit.sqlite3");
    let receipt_key = SigningKey::generate(&mut OsRng);
    let facility =
        DefmiFacility::open(&database_path, authorizer.clone(), receipt_key.clone()).unwrap();
    let asset = register(
        &facility,
        &authorizer,
        &nodes,
        "JPY-GUARANTEE",
        AssetKind::Cash,
        0,
    );
    let guarantor = SigningKey::generate(&mut OsRng);
    let definition = GuarantorDefinition {
        guarantor_id: h("guarantor:ccp-or-bank"),
        kind,
        name: "Test guarantee provider".into(),
        public_key: guarantor.verifying_key().to_bytes(),
        risk_policy_digest: h("risk-policy:v1"),
    };
    facility
        .register_guarantor(
            &definition,
            &approve(
                &facility,
                &authorizer,
                &nodes,
                definition.statement().unwrap(),
                3,
            ),
        )
        .unwrap();
    let cap_blinding = Scalar::random(&mut OsRng);
    let cap = credit_commit(100, &cap_blinding);
    let collateral_blinding = Scalar::random(&mut OsRng);
    let mut grant = CreditFacilityGrant {
        operation_id: h("credit:grant"),
        facility_id: h("credit:facility"),
        guarantor_id: definition.guarantor_id,
        beneficiary_commitment: h("entity:beneficiary"),
        rail_asset_id: asset.asset_id,
        cap_commitment: cap,
        available_commitment: cap,
        held_commitment: ZERO,
        outstanding_commitment: ZERO,
        collateral_commitment: credit_commit(150, &collateral_blinding),
        risk_policy_digest: definition.risk_policy_digest,
        relation_proof_digest: h("credit:grant-proof"),
        valid_from: 1,
        valid_until: 10_000,
        nonce: h("credit:grant-nonce"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    grant.guarantor_signature = guarantor.sign(&grant.guarantor_message().unwrap());
    facility
        .grant_credit_facility(
            &grant,
            &approve(
                &facility,
                &authorizer,
                &nodes,
                grant.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    CreditFixture {
        _directory: directory,
        facility,
        authorizer,
        nodes,
        guarantor,
        facility_id: grant.facility_id,
        cap_blinding,
        collateral_blinding,
        database_path,
        receipt_key,
    }
}

// Keep each commitment and opening explicit: collapsing these cryptographic
// fixture values into defaults would make cross-state tests easier to misread.
#[allow(clippy::too_many_arguments)]
fn hold_transition(
    fixture: &CreditFixture,
    label: &str,
    before_sequence: u64,
    before_available: [u8; 32],
    before_held: [u8; 32],
    before_outstanding: [u8; 32],
    before_available_blinding: Scalar,
    before_held_blinding: Scalar,
    amount: u64,
    amount_blinding: Scalar,
) -> (CreditFacilityTransition, CreditFacilityRelationProof) {
    let after_available = 100u64
        .checked_sub(amount)
        .expect("test hold amount must be within the cap");
    let after_available_blinding = before_available_blinding - amount_blinding;
    let after_held_blinding = before_held_blinding + amount_blinding;
    let mut transition = CreditFacilityTransition {
        operation_id: h(&format!("credit:hold-operation:{label}")),
        facility_id: fixture.facility_id,
        hold_id: h(&format!("credit:hold:{label}")),
        kind: CreditTransitionKind::Hold,
        query_commitment: h(&format!("rfq:{label}")),
        amount_commitment: credit_commit(amount, &amount_blinding),
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: before_available,
        after_available_commitment: credit_commit(after_available, &after_available_blinding),
        before_held_commitment: before_held,
        after_held_commitment: credit_commit(amount, &after_held_blinding),
        before_outstanding_commitment: before_outstanding,
        after_outstanding_commitment: before_outstanding,
        before_sequence,
        expires_at: 1_000,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    let proof = CreditFacilityRelationProof::prove(
        &mut transition,
        [after_available, amount, 0, amount],
        [
            after_available_blinding,
            after_held_blinding,
            Scalar::ZERO,
            amount_blinding,
        ],
        [0, 0],
        [Scalar::ZERO, Scalar::ZERO],
        &mut OsRng,
    )
    .unwrap();
    (transition, proof)
}

fn bound_hold_transition(
    facility_id: [u8; 32],
    label: &str,
    authorization_digest: [u8; 32],
    cap_blinding: Scalar,
    amount: u64,
    amount_blinding: Scalar,
) -> (CreditFacilityTransition, CreditFacilityRelationProof) {
    let available = 100 - amount;
    let available_blinding = cap_blinding - amount_blinding;
    let mut transition = CreditFacilityTransition {
        operation_id: h(&format!("product:hold-operation:{label}")),
        facility_id,
        hold_id: h(&format!("product:hold:{label}")),
        kind: CreditTransitionKind::Hold,
        query_commitment: authorization_digest,
        amount_commitment: credit_commit(amount, &amount_blinding),
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: credit_commit(100, &cap_blinding),
        after_available_commitment: credit_commit(available, &available_blinding),
        before_held_commitment: ZERO,
        after_held_commitment: credit_commit(amount, &amount_blinding),
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: ZERO,
        before_sequence: 0,
        expires_at: 1_000,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    let proof = CreditFacilityRelationProof::prove(
        &mut transition,
        [available, amount, 0, amount],
        [
            available_blinding,
            amount_blinding,
            Scalar::ZERO,
            amount_blinding,
        ],
        [0, 0],
        [Scalar::ZERO, Scalar::ZERO],
        &mut OsRng,
    )
    .unwrap();
    (transition, proof)
}

#[test]
fn credit_relation_proof_wire_round_trips_and_rejects_malformed_frames() {
    let cap_blinding = Scalar::from(41_u64);
    let (transition, proof) = bound_hold_transition(
        h("wire-facility"),
        "wire",
        h("wire-authorization"),
        cap_blinding,
        17,
        Scalar::from(9_u64),
    );
    let wire = proof.to_bytes().unwrap();
    CreditFacilityRelationProof::from_bytes(&wire)
        .unwrap()
        .verify(&transition)
        .unwrap();

    let mut wrong_magic = wire.clone();
    wrong_magic[0] ^= 1;
    assert!(CreditFacilityRelationProof::from_bytes(&wrong_magic).is_err());
    assert!(CreditFacilityRelationProof::from_bytes(&wire[..wire.len() - 1]).is_err());
    let mut trailing = wire;
    trailing.push(0);
    assert!(CreditFacilityRelationProof::from_bytes(&trailing).is_err());
}

fn release_transition(
    hold: &CreditFacilityTransition,
    label: &str,
    cap_blinding: Scalar,
    amount: u64,
    amount_blinding: Scalar,
) -> (CreditFacilityTransition, CreditFacilityRelationProof) {
    let before_available_blinding = cap_blinding - amount_blinding;
    let mut transition = CreditFacilityTransition {
        operation_id: h(&format!("product:release-operation:{label}")),
        facility_id: hold.facility_id,
        hold_id: hold.hold_id,
        kind: CreditTransitionKind::Release,
        query_commitment: hold.query_commitment,
        amount_commitment: hold.amount_commitment,
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: credit_commit(100 - amount, &before_available_blinding),
        after_available_commitment: credit_commit(100, &cap_blinding),
        before_held_commitment: credit_commit(amount, &amount_blinding),
        after_held_commitment: ZERO,
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: ZERO,
        before_sequence: hold.before_sequence + 1,
        expires_at: hold.expires_at,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    let proof = CreditFacilityRelationProof::prove(
        &mut transition,
        [100, 0, 0, amount],
        [cap_blinding, Scalar::ZERO, Scalar::ZERO, amount_blinding],
        [0, 0],
        [Scalar::ZERO, Scalar::ZERO],
        &mut OsRng,
    )
    .unwrap();
    (transition, proof)
}

fn frost_sign(
    shares: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
    message: &[u8],
) -> frost::Signature {
    let chosen: Vec<_> = shares.keys().take(3).copied().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (nonce, commitment) = frost::round1::commit(shares[id].signing_share(), &mut OsRng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let signature_shares = chosen
        .iter()
        .map(|id| {
            (
                *id,
                frost::round2::sign(&package, &nonces[id], &shares[id]).unwrap(),
            )
        })
        .collect();
    frost::aggregate(&package, &signature_shares, public).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn threshold_settlement_payment(
    issuer: &Issuer,
    amount: u64,
    price: u64,
    asset_id: [u8; 32],
    payer_handle: RistrettoPoint,
    payee_handle: RistrettoPoint,
    deadline: u64,
    nonce: [u8; 32],
    quote_proof_digest: [u8; 32],
    shares: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
) -> (qomm_zkpi::Instruction, Openings) {
    let openings = Openings {
        amount: Scalar::random(&mut OsRng),
        price: Scalar::random(&mut OsRng),
        asset: Scalar::random(&mut OsRng),
    };
    let payment = threshold_payment_from_openings(
        issuer,
        amount,
        price,
        asset_id,
        payer_handle,
        payee_handle,
        deadline,
        nonce,
        quote_proof_digest,
        Openings {
            amount: openings.amount,
            price: openings.price,
            asset: openings.asset,
        },
        shares,
        public,
    );
    (payment, openings)
}

#[allow(clippy::too_many_arguments)]
fn threshold_payment_from_openings(
    issuer: &Issuer,
    amount: u64,
    price: u64,
    asset_id: [u8; 32],
    payer_handle: RistrettoPoint,
    payee_handle: RistrettoPoint,
    deadline: u64,
    nonce: [u8; 32],
    quote_proof_digest: [u8; 32],
    openings: Openings,
    shares: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
) -> qomm_zkpi::Instruction {
    let parties = [1usize, 2, 3, 4, 5, 6, 7];
    let quorum = [1usize, 2, 3];
    let amount_shares = deal_bits(
        &issuer.key,
        amount,
        &openings.amount,
        issuer.bounds.amount_bits,
        &parties,
        2,
        &mut OsRng,
    )
    .unwrap();
    let price_shares = deal_bits(
        &issuer.key,
        price,
        &openings.price,
        issuer.bounds.price_bits,
        &parties,
        2,
        &mut OsRng,
    )
    .unwrap();
    let amount_nodes = quorum
        .iter()
        .map(|party| amount_shares.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    let price_nodes = quorum
        .iter()
        .map(|party| price_shares.node_contribution(*party).unwrap())
        .collect::<Vec<_>>();
    let (amount_range, _) = joint_prove_range_from_contributions(
        &issuer.key,
        &amount_nodes,
        &quorum,
        AMOUNT_RANGE_CONTEXT,
        &mut OsRng,
    )
    .unwrap();
    let (price_range, _) = joint_prove_range_from_contributions(
        &issuer.key,
        &price_nodes,
        &quorum,
        PRICE_RANGE_CONTEXT,
        &mut OsRng,
    )
    .unwrap();
    let partial = PartialInstruction::from_threshold_ranges(
        &issuer.key,
        &issuer.bounds,
        amount_shares.commitment,
        price_shares.commitment,
        issuer.key.commit(&asset_scalar(&asset_id), &openings.asset),
        amount_range,
        price_range,
        payer_handle,
        payee_handle,
        deadline,
        nonce,
        quote_proof_digest,
    )
    .unwrap();
    let digest = partial.digest_for(&issuer.domain);
    partial.sealed(frost_sign(shares, public, &digest))
}

#[test]
fn one_state_machine_settles_security_fx_fund_and_carbon() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let jpy = register(&facility, &authorizer, &keys, "JPY", AssetKind::Cash, 0);
    let usd = register(&facility, &authorizer, &keys, "USD", AssetKind::Cash, 2);
    let security = register(
        &facility,
        &authorizer,
        &keys,
        "JP0000000001",
        AssetKind::Security,
        0,
    );
    let fund = register(&facility, &authorizer, &keys, "FUND-A", AssetKind::Fund, 6);
    let carbon = register(
        &facility,
        &authorizer,
        &keys,
        "J-CREDIT",
        AssetKind::Carbon,
        0,
    );
    assert_eq!(facility.asset_count().unwrap(), 5);

    let sec_s = opening(&facility, &authorizer, &keys, "sec-s", &security, h("s1"));
    let sec_b = opening(&facility, &authorizer, &keys, "sec-b", &security, h("s2"));
    let jpy_b = opening(&facility, &authorizer, &keys, "jpy-b", &jpy, h("j1"));
    let jpy_s = opening(&facility, &authorizer, &keys, "jpy-s", &jpy, h("j2"));
    let dvp = order(
        "dvp",
        vec![
            leg(&sec_s, &security, h("s1"), h("s11"), 0),
            leg(&sec_b, &security, h("s2"), h("s12"), 0),
            leg(&jpy_b, &jpy, h("j1"), h("j11"), 0),
            leg(&jpy_s, &jpy, h("j2"), h("j12"), 0),
        ],
        1_000,
    );
    let receipt = facility
        .settle(
            &dvp,
            &approve(&facility, &authorizer, &keys, dvp.statement().unwrap(), 3),
            100,
        )
        .unwrap();
    assert!(receipt.verify(&facility.receipt_public_key));

    let usd_a = opening(&facility, &authorizer, &keys, "usd-a", &usd, h("u1"));
    let usd_b = opening(&facility, &authorizer, &keys, "usd-b", &usd, h("u2"));
    let jpy_a = opening(&facility, &authorizer, &keys, "jpy-a", &jpy, h("ja1"));
    let jpy_c = opening(&facility, &authorizer, &keys, "jpy-c", &jpy, h("ja2"));
    let pvp = order(
        "pvp",
        vec![
            leg(&usd_a, &usd, h("u1"), h("u11"), 0),
            leg(&usd_b, &usd, h("u2"), h("u12"), 0),
            leg(&jpy_a, &jpy, h("ja1"), h("ja11"), 0),
            leg(&jpy_c, &jpy, h("ja2"), h("ja12"), 0),
        ],
        1_000,
    );
    facility
        .settle(
            &pvp,
            &approve(&facility, &authorizer, &keys, pvp.statement().unwrap(), 3),
            101,
        )
        .unwrap();

    for (asset, label) in [(&fund, "fund"), (&carbon, "carbon")] {
        let left = opening(
            &facility,
            &authorizer,
            &keys,
            &format!("{label}-a"),
            asset,
            h(&format!("{label}1")),
        );
        let right = opening(
            &facility,
            &authorizer,
            &keys,
            &format!("{label}-b"),
            asset,
            h(&format!("{label}2")),
        );
        let transfer = order(
            label,
            vec![
                leg(
                    &left,
                    asset,
                    h(&format!("{label}1")),
                    h(&format!("{label}11")),
                    0,
                ),
                leg(
                    &right,
                    asset,
                    h(&format!("{label}2")),
                    h(&format!("{label}12")),
                    0,
                ),
            ],
            1_000,
        );
        facility
            .settle(
                &transfer,
                &approve(
                    &facility,
                    &authorizer,
                    &keys,
                    transfer.statement().unwrap(),
                    3,
                ),
                102,
            )
            .unwrap();
    }
    assert!(facility.verify_receipt_chain().unwrap());
}

#[test]
fn stale_later_leg_rolls_back_every_leg_and_nullifier() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let jpy = register(&facility, &authorizer, &keys, "JPY", AssetKind::Cash, 0);
    let a = opening(&facility, &authorizer, &keys, "a", &jpy, h("a1"));
    let b = opening(&facility, &authorizer, &keys, "b", &jpy, h("b1"));
    let bad = order(
        "bad",
        vec![
            leg(&a, &jpy, h("a1"), h("a2"), 0),
            leg(&b, &jpy, h("wrong"), h("b2"), 0),
        ],
        1_000,
    );
    let before = facility.state_root().unwrap();
    let error = facility
        .settle(
            &bad,
            &approve(&facility, &authorizer, &keys, bad.statement().unwrap(), 3),
            100,
        )
        .unwrap_err();
    assert!(error.contains("stale"));
    assert_eq!(facility.account(&a.handle).unwrap().unwrap().1, h("a1"));
    assert_eq!(facility.state_root().unwrap(), before);
}

#[test]
fn quorum_expiry_replay_nullifier_and_wrong_asset_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let jpy = register(&facility, &authorizer, &keys, "JPY", AssetKind::Cash, 0);
    let usd = register(&facility, &authorizer, &keys, "USD", AssetKind::Cash, 0);
    let a = opening(&facility, &authorizer, &keys, "a", &jpy, h("a1"));
    let b = opening(&facility, &authorizer, &keys, "b", &jpy, h("b1"));
    let good = order(
        "good",
        vec![
            leg(&a, &jpy, h("a1"), h("a2"), 0),
            leg(&b, &jpy, h("b1"), h("b2"), 0),
        ],
        1_000,
    );
    assert!(facility
        .settle(
            &good,
            &approve(&facility, &authorizer, &keys, good.statement().unwrap(), 2),
            100,
        )
        .unwrap_err()
        .contains("k-of-n"));
    assert!(facility
        .settle(
            &good,
            &approve(&facility, &authorizer, &keys, good.statement().unwrap(), 3),
            1_001,
        )
        .unwrap_err()
        .contains("expired"));
    let approval = approve(&facility, &authorizer, &keys, good.statement().unwrap(), 3);
    let receipt = facility.settle(&good, &approval, 100).unwrap();
    assert_eq!(
        facility
            .settle(&good, &approval, 1_001)
            .unwrap()
            .digest()
            .unwrap(),
        receipt.digest().unwrap()
    );

    let reused = SettlementOrder {
        operation_id: h("operation:other"),
        nullifier: good.nullifier,
        deadline: 1_000,
        payment_instruction_digest: h("zkpi:other"),
        proof_digest: h("proof:other"),
        market_statement_digest: h("market:other"),
        legs: vec![leg(&a, &usd, h("a2"), h("a3"), 1)],
    };
    let error = facility
        .settle(
            &reused,
            &approve(
                &facility,
                &authorizer,
                &keys,
                reused.statement().unwrap(),
                3,
            ),
            101,
        )
        .unwrap_err();
    assert!(error.contains("nullifier") || error.contains("asset"));
}

#[test]
fn persistence_backup_cost_meter_and_chain_survive_restart() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let receipt_key = SigningKey::generate(&mut OsRng);
    let path = directory.path().join("defmi.sqlite3");
    let facility = DefmiFacility::open(&path, authorizer.clone(), receipt_key.clone()).unwrap();
    let jpy = register(&facility, &authorizer, &keys, "JPY", AssetKind::Cash, 0);
    let a = opening(&facility, &authorizer, &keys, "a", &jpy, h("a1"));
    let b = opening(&facility, &authorizer, &keys, "b", &jpy, h("b1"));
    let transfer = order(
        "persist",
        vec![
            leg(&a, &jpy, h("a1"), h("a2"), 0),
            leg(&b, &jpy, h("b1"), h("b2"), 0),
        ],
        1_000,
    );
    let receipt = facility
        .settle(
            &transfer,
            &approve(
                &facility,
                &authorizer,
                &keys,
                transfer.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    assert!(receipt.elapsed_ns > 0 && receipt.request_bytes > 0);
    assert!(receipt.database_bytes_after >= receipt.database_bytes_before);
    let backup = facility
        .backup(directory.path().join("backup.sqlite3"))
        .unwrap();
    assert!(backup.metadata().unwrap().len() > 0);
    facility.checkpoint().unwrap();
    drop(facility);

    let reopened = DefmiFacility::open(&path, authorizer, receipt_key).unwrap();
    assert_eq!(reopened.account(&a.handle).unwrap().unwrap().1, h("a2"));
    assert_eq!(reopened.account(&a.handle).unwrap().unwrap().2, 1);
    assert!(reopened.verify_receipt_chain().unwrap());
}

#[test]
fn asset_and_account_retries_are_idempotent_but_conflicts_fail() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let asset = AssetDefinition {
        asset_id: h("asset:JPY"),
        code: "JPY".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: h("terms:JPY"),
    };
    let approval = approve(&facility, &authorizer, &keys, asset.statement().unwrap(), 3);
    facility.register_asset(&asset, &approval).unwrap();
    facility.register_asset(&asset, &approval).unwrap();
    let conflict = AssetDefinition {
        asset_id: asset.asset_id,
        code: "USD".into(),
        kind: AssetKind::Cash,
        decimals: 2,
        terms_digest: h("terms:USD"),
    };
    assert!(facility
        .register_asset(
            &conflict,
            &approve(
                &facility,
                &authorizer,
                &keys,
                conflict.statement().unwrap(),
                3,
            ),
        )
        .unwrap_err()
        .contains("reused"));

    let account = AccountOpening {
        handle: h("account:a"),
        asset_id: asset.asset_id,
        commitment: h("a1"),
        issuance_nonce: h("issuance:a"),
    };
    let approval = approve(
        &facility,
        &authorizer,
        &keys,
        account.statement().unwrap(),
        3,
    );
    facility.open_account(&account, &approval).unwrap();
    facility.open_account(&account, &approval).unwrap();
    let conflict = AccountOpening {
        commitment: h("a2"),
        issuance_nonce: h("issuance:b"),
        ..account
    };
    assert!(facility
        .open_account(
            &conflict,
            &approve(
                &facility,
                &authorizer,
                &keys,
                conflict.statement().unwrap(),
                3,
            ),
        )
        .unwrap_err()
        .contains("reused"));
}

#[test]
fn quorum_is_bound_to_unique_keys_domain_and_before_root() {
    let repeated = SigningKey::generate(&mut OsRng);
    assert!(QuorumAuthorizer::new(
        BTreeMap::from([
            ("node-a".into(), repeated.verifying_key()),
            ("node-b".into(), repeated.verifying_key()),
        ]),
        2,
        1,
        "defmi:local",
    )
    .unwrap_err()
    .contains("two node identities"));

    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let authorizer = authorizer(&keys);
    let facility = DefmiFacility::open(
        directory.path().join("defmi.sqlite3"),
        authorizer.clone(),
        SigningKey::generate(&mut OsRng),
    )
    .unwrap();
    let pending = AssetDefinition {
        asset_id: h("asset:pending"),
        code: "PENDING".into(),
        kind: AssetKind::Other,
        decimals: 0,
        terms_digest: h("terms:pending"),
    };
    let stale = approve(
        &facility,
        &authorizer,
        &keys,
        pending.statement().unwrap(),
        3,
    );
    register(&facility, &authorizer, &keys, "OTHER", AssetKind::Other, 0);
    assert!(facility
        .register_asset(&pending, &stale)
        .unwrap_err()
        .contains("k-of-n"));

    let foreign = QuorumAuthorizer::new(
        keys.iter()
            .map(|(node, key)| (node.clone(), key.verifying_key()))
            .collect(),
        3,
        1,
        "another-avalanche-chain",
    )
    .unwrap();
    let signers = keys
        .iter()
        .take(3)
        .map(|(node, key)| (node.clone(), key.clone()))
        .collect();
    let foreign_approval = foreign
        .approve(
            pending.statement().unwrap(),
            facility.state_root().unwrap(),
            &signers,
        )
        .unwrap();
    assert!(facility
        .register_asset(&pending, &foreign_approval)
        .unwrap_err()
        .contains("k-of-n"));
}

#[test]
fn zero_identifiers_are_rejected_before_authorization() {
    assert!(AssetDefinition {
        asset_id: ZERO,
        code: "JPY".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: h("terms"),
    }
    .body()
    .unwrap_err()
    .contains("all-zero"));
    assert!(AccountOpening {
        handle: h("handle"),
        asset_id: h("asset"),
        commitment: ZERO,
        issuance_nonce: h("nonce"),
    }
    .body()
    .unwrap_err()
    .contains("all-zero"));
    assert!(SettlementOrder {
        operation_id: h("operation"),
        nullifier: ZERO,
        deadline: 1_000,
        payment_instruction_digest: h("zkpi"),
        proof_digest: h("proof"),
        market_statement_digest: h("market"),
        legs: vec![StateLeg {
            handle: h("handle"),
            asset_id: h("asset"),
            before_commitment: h("before"),
            after_commitment: h("after"),
            before_sequence: 0,
        }],
    }
    .body()
    .unwrap_err()
    .contains("all-zero"));
}

#[test]
fn one_guarantor_cannot_split_an_entity_cap_across_two_facility_ids() {
    let fixture = credit_fixture();
    let cap_blinding = Scalar::random(&mut OsRng);
    let cap = credit_commit(100, &cap_blinding);
    let mut duplicate = CreditFacilityGrant {
        operation_id: h("credit:duplicate-scope-grant"),
        facility_id: h("credit:duplicate-scope-facility"),
        guarantor_id: h("guarantor:ccp-or-bank"),
        beneficiary_commitment: h("entity:beneficiary"),
        rail_asset_id: h("asset:JPY-GUARANTEE"),
        cap_commitment: cap,
        available_commitment: cap,
        held_commitment: ZERO,
        outstanding_commitment: ZERO,
        collateral_commitment: credit_commit(150, &Scalar::random(&mut OsRng)),
        risk_policy_digest: h("risk-policy:v1"),
        relation_proof_digest: h("credit:duplicate-scope-proof"),
        valid_from: 1,
        valid_until: 10_000,
        nonce: h("credit:duplicate-scope-nonce"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    duplicate.guarantor_signature = fixture
        .guarantor
        .sign(&duplicate.guarantor_message().unwrap());
    let approval = approve(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        duplicate.statement().unwrap(),
        3,
    );

    assert!(fixture
        .facility
        .grant_credit_facility(&duplicate, &approval, 100)
        .unwrap_err()
        .contains("legal entity and asset rail"));
    assert!(fixture
        .facility
        .credit_facility(&duplicate.facility_id)
        .unwrap()
        .is_none());
}

#[test]
fn credit_holds_are_private_atomic_and_cannot_overdraw_the_cap() {
    let fixture = credit_fixture();
    let cap = credit_commit(100, &fixture.cap_blinding);
    let amount_blinding = Scalar::random(&mut OsRng);
    let (first, first_proof) = hold_transition(
        &fixture,
        "first",
        0,
        cap,
        ZERO,
        ZERO,
        fixture.cap_blinding,
        Scalar::ZERO,
        70,
        amount_blinding,
    );
    let (concurrent, concurrent_proof) = hold_transition(
        &fixture,
        "concurrent",
        0,
        cap,
        ZERO,
        ZERO,
        fixture.cap_blinding,
        Scalar::ZERO,
        50,
        Scalar::random(&mut OsRng),
    );
    // Both requests were signed against the same pre-state, as two genuinely
    // concurrent admissions would be.
    let first_approval = approve(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        first.statement().unwrap(),
        3,
    );
    let concurrent_approval = approve(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        concurrent.statement().unwrap(),
        3,
    );
    let current = fixture
        .facility
        .transition_credit_facility(&first, &first_proof, &first_approval, 100)
        .unwrap();
    assert_eq!(current.sequence, 1);
    assert_eq!(current.status, CreditFacilityStatus::Active);
    assert!(fixture
        .facility
        .transition_credit_facility(&concurrent, &concurrent_proof, &concurrent_approval, 100,)
        .unwrap_err()
        .contains("k-of-n"));

    // An amount above the hidden cap has no 64-bit non-negative remainder,
    // hence no proof can be constructed even if a caller invents a digest.
    let over_blinding = Scalar::random(&mut OsRng);
    let amount_point =
        Pedersen::new(b"qomm:defmi:credit-facility:v1").commit_u64(120, &over_blinding);
    let cap_point = CompressedRistretto(cap).decompress().unwrap();
    let impossible_remainder = (cap_point - amount_point).compress().to_bytes();
    let mut over = CreditFacilityTransition {
        operation_id: h("credit:over-operation"),
        facility_id: fixture.facility_id,
        hold_id: h("credit:over-hold"),
        kind: CreditTransitionKind::Hold,
        query_commitment: h("rfq:over"),
        amount_commitment: amount_point.compress().to_bytes(),
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: cap,
        after_available_commitment: impossible_remainder,
        before_held_commitment: ZERO,
        after_held_commitment: amount_point.compress().to_bytes(),
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: ZERO,
        before_sequence: 0,
        expires_at: 1_000,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    assert!(CreditFacilityRelationProof::prove(
        &mut over,
        [0, 120, 0, 120],
        [
            fixture.cap_blinding - over_blinding,
            over_blinding,
            Scalar::ZERO,
            over_blinding,
        ],
        [0, 0],
        [Scalar::ZERO, Scalar::ZERO],
        &mut OsRng,
    )
    .unwrap_err()
    .contains("do not match"));
}

fn simultaneous_rfqs_for(kind: GuarantorKind) {
    let fixture = credit_fixture_for(kind);
    let cap = credit_commit(100, &fixture.cap_blinding);
    let (left, left_proof) = hold_transition(
        &fixture,
        "real-concurrent-left",
        0,
        cap,
        ZERO,
        ZERO,
        fixture.cap_blinding,
        Scalar::ZERO,
        70,
        Scalar::random(&mut OsRng),
    );
    let (right, right_proof) = hold_transition(
        &fixture,
        "real-concurrent-right",
        0,
        cap,
        ZERO,
        ZERO,
        fixture.cap_blinding,
        Scalar::ZERO,
        50,
        Scalar::random(&mut OsRng),
    );
    let left_approval = approve(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        left.statement().unwrap(),
        3,
    );
    let right_approval = approve(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        right.statement().unwrap(),
        3,
    );
    let barrier = Arc::new(Barrier::new(2));
    let left_barrier = Arc::clone(&barrier);
    let right_barrier = Arc::clone(&barrier);
    let left_path = fixture.database_path.clone();
    let right_path = fixture.database_path.clone();
    let left_authorizer = fixture.authorizer.clone();
    let right_authorizer = fixture.authorizer.clone();
    let left_receipt_key = fixture.receipt_key.clone();
    let right_receipt_key = fixture.receipt_key.clone();
    let (left_result, right_result) = std::thread::scope(|scope| {
        let left_worker = scope.spawn(move || {
            let facility =
                DefmiFacility::open(left_path, left_authorizer, left_receipt_key).unwrap();
            left_barrier.wait();
            facility.transition_credit_facility(&left, &left_proof, &left_approval, 100)
        });
        let right_worker = scope.spawn(move || {
            let facility =
                DefmiFacility::open(right_path, right_authorizer, right_receipt_key).unwrap();
            right_barrier.wait();
            facility.transition_credit_facility(&right, &right_proof, &right_approval, 100)
        });
        (left_worker.join().unwrap(), right_worker.join().unwrap())
    });
    assert_eq!(
        usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
        1
    );
    let rejection = left_result
        .as_ref()
        .err()
        .or_else(|| right_result.as_ref().err())
        .unwrap();
    assert!(
        rejection.contains("k-of-n")
            || rejection.contains("stale")
            || rejection.contains("compare-and-swap"),
        "unexpected contention rejection: {rejection}"
    );
    let final_state = fixture
        .facility
        .credit_facility(&fixture.facility_id)
        .unwrap()
        .unwrap();
    let winner = left_result
        .as_ref()
        .ok()
        .or_else(|| right_result.as_ref().ok())
        .unwrap();
    assert_eq!(final_state.sequence, 1);
    assert_eq!(
        final_state.available_commitment,
        winner.available_commitment
    );
    assert_eq!(final_state.held_commitment, winner.held_commitment);
}

#[test]
fn simultaneous_rfqs_enforce_one_cap_for_ccp_bank_credit_provider_and_self_guarantee() {
    for kind in [
        GuarantorKind::CentralCounterparty,
        GuarantorKind::Bank,
        GuarantorKind::CreditProvider,
        GuarantorKind::SelfGuaranteed,
    ] {
        simultaneous_rfqs_for(kind);
    }
}

#[test]
fn reducing_a_facility_below_existing_usage_freezes_without_erasing_exposure() {
    let fixture = credit_fixture();
    let hold_blinding = Scalar::random(&mut OsRng);
    let cap = credit_commit(100, &fixture.cap_blinding);
    let (hold, hold_proof) = hold_transition(
        &fixture,
        "amend-over-limit",
        0,
        cap,
        ZERO,
        ZERO,
        fixture.cap_blinding,
        Scalar::ZERO,
        70,
        hold_blinding,
    );
    let held = fixture
        .facility
        .transition_credit_facility(
            &hold,
            &hold_proof,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                hold.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();

    let reduced_cap_blinding = Scalar::random(&mut OsRng);
    let excess_blinding = hold_blinding - reduced_cap_blinding;
    let mut reduction = CreditFacilityAmendment {
        operation_id: h("credit:amend:reduce"),
        facility_id: fixture.facility_id,
        mode: CreditAmendmentMode::OverLimit,
        before_cap_commitment: held.cap_commitment,
        after_cap_commitment: credit_commit(50, &reduced_cap_blinding),
        before_available_commitment: held.available_commitment,
        after_available_commitment: ZERO,
        before_held_commitment: held.held_commitment,
        before_outstanding_commitment: held.outstanding_commitment,
        before_overlimit_commitment: held.overlimit_commitment,
        after_overlimit_commitment: credit_commit(20, &excess_blinding),
        before_collateral_commitment: held.collateral_commitment,
        after_collateral_commitment: held.collateral_commitment,
        before_risk_policy_digest: held.risk_policy_digest,
        after_risk_policy_digest: held.risk_policy_digest,
        before_valid_until: held.valid_until,
        after_valid_until: 9_000,
        before_sequence: held.sequence,
        effective_at: 101,
        reason_digest: h("credit:amend:reduce:reason"),
        relation_proof_digest: ZERO,
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    let reduction_proof = CreditFacilityAmendmentProof::prove(
        &mut reduction,
        [50, 0, 70, 0],
        [
            reduced_cap_blinding,
            Scalar::ZERO,
            hold_blinding,
            Scalar::ZERO,
        ],
        [150, 20],
        [fixture.collateral_blinding, excess_blinding],
        &mut OsRng,
    )
    .unwrap();
    reduction.guarantor_signature = fixture
        .guarantor
        .sign(&reduction.guarantor_message().unwrap());
    let reduced = fixture
        .facility
        .amend_credit_facility(
            &reduction,
            &reduction_proof,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                reduction.statement().unwrap(),
                3,
            ),
            101,
        )
        .unwrap();
    assert_eq!(reduced.status, CreditFacilityStatus::Frozen);
    assert_eq!(reduced.held_commitment, held.held_commitment);
    assert_eq!(reduced.outstanding_commitment, held.outstanding_commitment);
    assert_eq!(reduced.available_commitment, ZERO);
    assert_eq!(
        reduced.overlimit_commitment,
        reduction.after_overlimit_commitment
    );

    let mut premature_activation = CreditFacilityControl {
        operation_id: h("credit:activate:premature"),
        facility_id: fixture.facility_id,
        action: CreditControlAction::Activate,
        before_sequence: reduced.sequence,
        effective_at: 102,
        reason_digest: h("credit:activate:premature:reason"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    premature_activation.guarantor_signature = fixture
        .guarantor
        .sign(&premature_activation.guarantor_message().unwrap());
    assert!(fixture
        .facility
        .control_credit_facility(
            &premature_activation,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                premature_activation.statement().unwrap(),
                3,
            ),
            102,
        )
        .unwrap_err()
        .contains("over-limit"));

    // Expiry returns the held amount to a bookkeeping balance, but the line
    // remains frozen.  This prevents an amendment from manufacturing new
    // spendable capacity while preserving the exact old obligation.
    let mut release = CreditFacilityTransition {
        operation_id: h("credit:release:after-reduction"),
        facility_id: fixture.facility_id,
        hold_id: hold.hold_id,
        kind: CreditTransitionKind::Release,
        query_commitment: hold.query_commitment,
        amount_commitment: hold.amount_commitment,
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: reduced.available_commitment,
        after_available_commitment: credit_commit(70, &hold_blinding),
        before_held_commitment: reduced.held_commitment,
        after_held_commitment: ZERO,
        before_outstanding_commitment: reduced.outstanding_commitment,
        after_outstanding_commitment: reduced.outstanding_commitment,
        before_sequence: reduced.sequence,
        expires_at: hold.expires_at,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    let release_proof = CreditFacilityRelationProof::prove(
        &mut release,
        [70, 0, 0, 70],
        [hold_blinding, Scalar::ZERO, Scalar::ZERO, hold_blinding],
        [0, 0],
        [Scalar::ZERO, Scalar::ZERO],
        &mut OsRng,
    )
    .unwrap();
    let released = fixture
        .facility
        .transition_credit_facility(
            &release,
            &release_proof,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                release.statement().unwrap(),
                3,
            ),
            1_001,
        )
        .unwrap();
    assert_eq!(released.status, CreditFacilityStatus::Frozen);
    assert_eq!(released.held_commitment, ZERO);
    assert_eq!(released.overlimit_commitment, reduced.overlimit_commitment);

    // Guarantor explicitly rebalances the now-recovered line.  An amendment
    // clears the excess; a separate signed Activate operation is still needed.
    let mut rehabilitation = CreditFacilityAmendment {
        operation_id: h("credit:amend:rehabilitate"),
        facility_id: fixture.facility_id,
        mode: CreditAmendmentMode::WithinLimit,
        before_cap_commitment: released.cap_commitment,
        after_cap_commitment: credit_commit(50, &reduced_cap_blinding),
        before_available_commitment: released.available_commitment,
        after_available_commitment: credit_commit(50, &reduced_cap_blinding),
        before_held_commitment: released.held_commitment,
        before_outstanding_commitment: released.outstanding_commitment,
        before_overlimit_commitment: released.overlimit_commitment,
        after_overlimit_commitment: ZERO,
        before_collateral_commitment: released.collateral_commitment,
        after_collateral_commitment: released.collateral_commitment,
        before_risk_policy_digest: released.risk_policy_digest,
        after_risk_policy_digest: released.risk_policy_digest,
        before_valid_until: released.valid_until,
        after_valid_until: 9_000,
        before_sequence: released.sequence,
        effective_at: 1_002,
        reason_digest: h("credit:amend:rehabilitate:reason"),
        relation_proof_digest: ZERO,
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    let rehabilitation_proof = CreditFacilityAmendmentProof::prove(
        &mut rehabilitation,
        [50, 50, 0, 0],
        [
            reduced_cap_blinding,
            reduced_cap_blinding,
            Scalar::ZERO,
            Scalar::ZERO,
        ],
        [150, 0],
        [fixture.collateral_blinding, Scalar::ZERO],
        &mut OsRng,
    )
    .unwrap();
    rehabilitation.guarantor_signature = fixture
        .guarantor
        .sign(&rehabilitation.guarantor_message().unwrap());
    let rehabilitated = fixture
        .facility
        .amend_credit_facility(
            &rehabilitation,
            &rehabilitation_proof,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                rehabilitation.statement().unwrap(),
                3,
            ),
            1_002,
        )
        .unwrap();
    assert_eq!(rehabilitated.status, CreditFacilityStatus::Frozen);
    assert_eq!(rehabilitated.overlimit_commitment, ZERO);

    let mut activate = CreditFacilityControl {
        operation_id: h("credit:activate:after-rehabilitation"),
        facility_id: fixture.facility_id,
        action: CreditControlAction::Activate,
        before_sequence: rehabilitated.sequence,
        effective_at: 1_003,
        reason_digest: h("credit:activate:after-rehabilitation:reason"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    activate.guarantor_signature = fixture
        .guarantor
        .sign(&activate.guarantor_message().unwrap());
    let active = fixture
        .facility
        .control_credit_facility(
            &activate,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                activate.statement().unwrap(),
                3,
            ),
            1_003,
        )
        .unwrap();
    assert_eq!(active.status, CreditFacilityStatus::Active);
    assert_eq!(
        active.available_commitment,
        rehabilitation.after_available_commitment
    );
}

#[test]
fn frozen_facility_refuses_new_rfqs_but_existing_hold_can_expire() {
    let fixture = credit_fixture();
    let amount_blinding = Scalar::random(&mut OsRng);
    let cap = credit_commit(100, &fixture.cap_blinding);
    let (hold, hold_proof) = hold_transition(
        &fixture,
        "freeze",
        0,
        cap,
        ZERO,
        ZERO,
        fixture.cap_blinding,
        Scalar::ZERO,
        70,
        amount_blinding,
    );
    let held = fixture
        .facility
        .transition_credit_facility(
            &hold,
            &hold_proof,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                hold.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    let mut freeze = CreditFacilityControl {
        operation_id: h("credit:freeze"),
        facility_id: fixture.facility_id,
        action: CreditControlAction::Freeze,
        before_sequence: held.sequence,
        effective_at: 101,
        reason_digest: h("credit:freeze-reason"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    freeze.guarantor_signature = fixture.guarantor.sign(&freeze.guarantor_message().unwrap());
    let frozen = fixture
        .facility
        .control_credit_facility(
            &freeze,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                freeze.statement().unwrap(),
                3,
            ),
            101,
        )
        .unwrap();
    assert_eq!(frozen.status, CreditFacilityStatus::Frozen);
    assert_eq!(frozen.held_commitment, held.held_commitment);

    let mut release = CreditFacilityTransition {
        operation_id: h("credit:release"),
        facility_id: fixture.facility_id,
        hold_id: hold.hold_id,
        kind: CreditTransitionKind::Release,
        query_commitment: hold.query_commitment,
        amount_commitment: hold.amount_commitment,
        consumed_commitment: ZERO,
        refund_commitment: ZERO,
        before_available_commitment: frozen.available_commitment,
        after_available_commitment: cap,
        before_held_commitment: frozen.held_commitment,
        after_held_commitment: ZERO,
        before_outstanding_commitment: frozen.outstanding_commitment,
        after_outstanding_commitment: frozen.outstanding_commitment,
        before_sequence: frozen.sequence,
        expires_at: hold.expires_at,
        settlement_digest: ZERO,
        relation_proof_digest: ZERO,
    };
    let release_proof = CreditFacilityRelationProof::prove(
        &mut release,
        [100, 0, 0, 70],
        [
            fixture.cap_blinding,
            Scalar::ZERO,
            Scalar::ZERO,
            amount_blinding,
        ],
        [0, 0],
        [Scalar::ZERO, Scalar::ZERO],
        &mut OsRng,
    )
    .unwrap();
    let released = fixture
        .facility
        .transition_credit_facility(
            &release,
            &release_proof,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                release.statement().unwrap(),
                3,
            ),
            1_001,
        )
        .unwrap();
    assert_eq!(released.available_commitment, cap);
    assert_eq!(released.held_commitment, ZERO);
    assert_eq!(released.status, CreditFacilityStatus::Frozen);
}

#[test]
fn consuming_a_hold_moves_actual_debt_and_returns_the_unused_maximum() {
    let fixture = credit_fixture();
    let cap = credit_commit(100, &fixture.cap_blinding);
    let hold_blinding = Scalar::random(&mut OsRng);
    let (hold, hold_proof) = hold_transition(
        &fixture,
        "consume",
        0,
        cap,
        ZERO,
        ZERO,
        fixture.cap_blinding,
        Scalar::ZERO,
        70,
        hold_blinding,
    );
    let held = fixture
        .facility
        .transition_credit_facility(
            &hold,
            &hold_proof,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                hold.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    let consumed_blinding = Scalar::random(&mut OsRng);
    let refund_blinding = hold_blinding - consumed_blinding;
    let mut consume = CreditFacilityTransition {
        operation_id: h("credit:consume"),
        facility_id: fixture.facility_id,
        hold_id: hold.hold_id,
        kind: CreditTransitionKind::Consume,
        query_commitment: hold.query_commitment,
        amount_commitment: hold.amount_commitment,
        consumed_commitment: credit_commit(55, &consumed_blinding),
        refund_commitment: credit_commit(15, &refund_blinding),
        before_available_commitment: held.available_commitment,
        after_available_commitment: credit_commit(45, &(fixture.cap_blinding - consumed_blinding)),
        before_held_commitment: held.held_commitment,
        after_held_commitment: ZERO,
        before_outstanding_commitment: ZERO,
        after_outstanding_commitment: credit_commit(55, &consumed_blinding),
        before_sequence: held.sequence,
        expires_at: hold.expires_at,
        settlement_digest: h("zkpi:settlement:consume"),
        relation_proof_digest: ZERO,
    };
    let proof = CreditFacilityRelationProof::prove(
        &mut consume,
        [45, 0, 55, 70],
        [
            fixture.cap_blinding - consumed_blinding,
            Scalar::ZERO,
            consumed_blinding,
            hold_blinding,
        ],
        [55, 15],
        [consumed_blinding, refund_blinding],
        &mut OsRng,
    )
    .unwrap();
    let consumed = fixture
        .facility
        .transition_credit_facility(
            &consume,
            &proof,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                consume.statement().unwrap(),
                3,
            ),
            200,
        )
        .unwrap();
    assert_eq!(consumed.sequence, 2);
    assert_eq!(consumed.held_commitment, ZERO);
    assert_eq!(
        consumed.available_commitment,
        consume.after_available_commitment
    );
    assert_eq!(
        consumed.outstanding_commitment,
        consume.after_outstanding_commitment
    );
}

#[test]
fn expired_product_reservation_restores_asset_and_credit_atomically_without_owner_signature() {
    let fixture = credit_fixture();
    let cash = register(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        "RELEASE-CASH",
        AssetKind::Cash,
        0,
    );

    let mut kyb_issuer = KybIssuer::new(4, &mut OsRng);
    let credential = kyb_issuer
        .enroll(
            "release-maker-control",
            BusinessAttributes {
                jurisdiction: "JP".into(),
                entity_type: "regulated-dealer".into(),
                collateral_tier: 3,
            },
            &mut OsRng,
        )
        .unwrap();
    let required_cohort = cohort_id("JP", "regulated-dealer", 2);
    let registry = kyb_issuer.publish(&required_cohort, 8, 10_000).unwrap();
    let kyb_scope = b"qomm/product/legal-entity";
    let kyb_context = b"qomm/avalanche/defmi/product-v1";
    let presentation = present(&credential, &registry, kyb_scope, kyb_context, &mut OsRng).unwrap();
    let trusted_issuer = kyb_issuer.public_key();
    let entity = presentation.entity_commitment();

    let cap_blinding = Scalar::random(&mut OsRng);
    let cap = credit_commit(100, &cap_blinding);
    let facility_id = h("credit:release-product-facility");
    let mut grant = CreditFacilityGrant {
        operation_id: h("credit:release-product-grant"),
        facility_id,
        guarantor_id: h("guarantor:ccp-or-bank"),
        beneficiary_commitment: entity,
        rail_asset_id: cash.asset_id,
        cap_commitment: cap,
        available_commitment: cap,
        held_commitment: ZERO,
        outstanding_commitment: ZERO,
        collateral_commitment: credit_commit(150, &Scalar::random(&mut OsRng)),
        risk_policy_digest: h("risk-policy:v1"),
        relation_proof_digest: h("credit:release-product-grant-proof"),
        valid_from: 1,
        valid_until: 10_000,
        nonce: h("credit:release-product-grant-nonce"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    grant.guarantor_signature = fixture.guarantor.sign(&grant.guarantor_message().unwrap());
    fixture
        .facility
        .grant_credit_facility(
            &grant,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                grant.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();

    let (secret, public) = deal_quorum(7, 3, &mut OsRng).unwrap();
    let shares: BTreeMap<_, _> = secret
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let maker_handle = RistrettoPoint::mul_base(&Scalar::from(31u64));
    let taker_handle = RistrettoPoint::mul_base(&Scalar::from(32u64));
    let reserve_handle = reserve_handle_for(&facility_id);
    let issuer = Issuer::new(Pedersen::new(b"qomm:defmi:v1"), Bounds::default());
    let venue_id = h("venue:qomm");
    let defmi_id = h("defmi:avalanche-local");
    let policy_digest = h("maker-policy:release:v1");

    let (reserve_digest, reserve_openings, reserve_partial) = issuer
        .build_for_asset_id(
            40,
            1,
            cash.asset_id,
            maker_handle,
            reserve_handle,
            1_000,
            h("zkpi:release-reserve:nonce"),
            91,
            &mut OsRng,
        )
        .unwrap();
    let reserve_payment = reserve_partial.sealed(frost_sign(&shares, &public, &reserve_digest));
    let source_handle: [u8; 32] = account_of(&maker_handle, CASH_RAIL).try_into().unwrap();
    let escrow_handle: [u8; 32] = account_of(&reserve_handle, CASH_RAIL).try_into().unwrap();
    let source_blinding = Scalar::random(&mut OsRng);
    let source_before = issuer.key.commit_u64(100, &source_blinding);
    let source = opening_with_handle(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        "release-product-source",
        source_handle,
        &cash,
        source_before.compress().to_bytes(),
    );
    let (hold, hold_proof) = bound_hold_transition(
        facility_id,
        "maker-release",
        policy_digest,
        cap_blinding,
        40,
        reserve_openings.amount,
    );
    let maker_key = SigningKey::generate(&mut OsRng);
    let mandate = MakerPolicyMandate {
        venue_id,
        defmi_id,
        policy_digest,
        policy_version: 1,
        asset_id: cash.asset_id,
        direction: Direction::TakerSells,
        reserve_id: hold.hold_id,
        maximum_amount_commitment: hold.amount_commitment,
        maker_handle: maker_handle.compress().to_bytes(),
        entity_commitment: entity,
        kyb_presentation_digest: presentation.binding_digest(),
        valid_from: 1,
        valid_until: 1_000,
        auto_execute: true,
        maker_public: maker_key.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0; 64]),
    }
    .sign(&maker_key)
    .unwrap();
    let mandate_digest = mandate.digest().unwrap();
    let reserve_context = ExecutionContext {
        operation: OperationKind::Reserve,
        scope: AuthorizationScope::Maker,
        direction: TradeDirection::TakerSells,
        venue_id,
        defmi_id,
        maker_handle,
        taker_handle,
        reserve_handle,
        maker_reservation_id: hold.hold_id,
        maker_reservation_sequence: 0,
        taker_reservation_id: ZERO,
        taker_reservation_sequence: 0,
        rfq_nullifier: ZERO,
        taker_mandate_digest: ZERO,
        maker_policy_digest: policy_digest,
        maker_mandate_digest: mandate_digest,
        maker_reserve_receipt_digest: ZERO,
        taker_reserve_receipt_digest: ZERO,
        quote_proof_digest: ZERO,
        market_statement_digest: ZERO,
        before_state_root: fixture.facility.state_root().unwrap(),
    };
    let reserve_authorization = frost_sign(
        &shares,
        &public,
        &typed_digest_for(&reserve_payment, &reserve_context, DEFAULT_DOMAIN).unwrap(),
    );
    let reserve_typed = TypedInstruction {
        payment: reserve_payment,
        context: reserve_context,
        authorization: reserve_authorization,
    };
    let reserve_link = qomm_defmi::asset_link::prove(
        &issuer.key,
        cash.asset_id,
        &reserve_typed.payment.asset_commitment,
        &reserve_openings.asset,
        &mut OsRng,
    )
    .unwrap();
    let mut source_ledger = Ledger::new(issuer.key.clone(), 32);
    source_ledger.open(&source_handle, source_before);
    let (escrow_transfer, _) = source_ledger
        .build_transfer_with_amount_blinding(
            100,
            &source_blinding,
            40,
            &reserve_openings.amount,
            &escrow_transfer_context(&hold.hold_id),
            None,
            &Scalar::ZERO,
            true,
        )
        .unwrap();
    let escrow_proof = ReservationEscrowProof {
        transfer: escrow_transfer,
    };
    let escrow = ReservationEscrow {
        source_handle,
        escrow_handle,
        asset_id: cash.asset_id,
        amount_commitment: hold.amount_commitment,
        source_before_commitment: source_before.compress().to_bytes(),
        source_after_commitment: escrow_proof
            .transfer
            .remainder_commitment
            .compress()
            .to_bytes(),
        source_before_sequence: 0,
        proof_digest: escrow_proof.digest(),
    };
    let authorization = ReservationAuthorization {
        role: ReservationRole::Maker,
        entity_commitment: entity,
        asset_id: cash.asset_id,
        direction: Direction::TakerSells as u8,
        authorization_digest: policy_digest,
        mandate_digest,
        typed_reserve_digest: Sha256::digest(typed_wire::encode(&reserve_typed)).into(),
        reserve_nullifier: reserve_typed.payment.nullifier(),
        asset_link_proof_digest: reserve_link
            .digest(&cash.asset_id, &reserve_typed.payment.asset_commitment),
        limit_price_commitment: ZERO,
        escrow_digest: escrow.statement().unwrap(),
        rfq_nullifier: ZERO,
        policy_version: 1,
        admission_ticket_id: ZERO,
        admission_slot: 0,
        admission_receipt_digest: ZERO,
        admission_epoch: 0,
        admission_sequence: 0,
        admission_batch_id: ZERO,
    };
    let reserve_receipt = authorization.statement(&hold).unwrap();
    let identity = IdentityEvidence {
        presentation: &presentation,
        registry: &registry,
        trusted_issuer: &trusted_issuer,
        scope: kyb_scope,
        context: kyb_context,
        required_cohort: &required_cohort,
    };
    let reserve_venue = Venue::new(
        Pedersen::new(b"qomm:defmi:v1"),
        &Bounds::default(),
        public.clone(),
    );
    reserve_maker(
        &fixture.facility,
        &hold,
        &hold_proof,
        &authorization,
        &escrow,
        &escrow_proof,
        &reserve_typed,
        &reserve_venue,
        &reserve_link,
        &mandate,
        &identity,
        &approve(
            &fixture.facility,
            &fixture.authorizer,
            &fixture.nodes,
            reserve_receipt,
            3,
        ),
        100,
    )
    .unwrap();
    assert_eq!(
        fixture.facility.account(&source.handle).unwrap().unwrap(),
        (cash.asset_id, escrow.source_after_commitment, 1)
    );

    let (release, release_proof) = release_transition(
        &hold,
        "maker-release",
        cap_blinding,
        40,
        reserve_openings.amount,
    );
    let release_openings = Openings {
        amount: reserve_openings.amount,
        price: Scalar::random(&mut OsRng),
        asset: Scalar::random(&mut OsRng),
    };
    let release_asset_blinding = release_openings.asset;
    let release_payment = threshold_payment_from_openings(
        &issuer,
        40,
        1,
        cash.asset_id,
        reserve_handle,
        maker_handle,
        1_200,
        h("zkpi:release:nonce"),
        ZERO,
        release_openings,
        &shares,
        &public,
    );
    let release_context = ExecutionContext {
        operation: OperationKind::Release,
        scope: AuthorizationScope::Maker,
        direction: TradeDirection::TakerSells,
        venue_id,
        defmi_id,
        maker_handle,
        taker_handle,
        reserve_handle,
        maker_reservation_id: hold.hold_id,
        maker_reservation_sequence: 1,
        taker_reservation_id: ZERO,
        taker_reservation_sequence: 0,
        rfq_nullifier: ZERO,
        taker_mandate_digest: ZERO,
        maker_policy_digest: policy_digest,
        maker_mandate_digest: mandate_digest,
        maker_reserve_receipt_digest: reserve_receipt,
        taker_reserve_receipt_digest: ZERO,
        quote_proof_digest: ZERO,
        market_statement_digest: ZERO,
        before_state_root: fixture.facility.state_root().unwrap(),
    };
    let release_typed = TypedInstruction {
        authorization: frost_sign(
            &shares,
            &public,
            &typed_digest_for(&release_payment, &release_context, DEFAULT_DOMAIN).unwrap(),
        ),
        payment: release_payment,
        context: release_context,
    };
    let release_link = qomm_defmi::asset_link::prove(
        &issuer.key,
        cash.asset_id,
        &release_typed.payment.asset_commitment,
        &release_asset_blinding,
        &mut OsRng,
    )
    .unwrap();
    let order = ProductReleaseOrder {
        transition: release,
        role: ReservationRole::Maker,
        reserve_receipt_digest: reserve_receipt,
        typed_instruction_digest: Sha256::digest(typed_wire::encode(&release_typed)).into(),
        release_nullifier: release_typed.payment.nullifier(),
        release_deadline: release_typed.payment.deadline,
        asset_id: cash.asset_id,
        asset_link_proof_digest: release_link
            .digest(&cash.asset_id, &release_typed.payment.asset_commitment),
        refund_leg: leg(
            &source,
            &cash,
            escrow.source_after_commitment,
            source_before.compress().to_bytes(),
            1,
        ),
    };
    let release_venue = Venue::new(Pedersen::new(b"qomm:defmi:v1"), &Bounds::default(), public)
        .require_threshold_ranges();

    let premature = release_reservation(
        &fixture.facility,
        &order,
        &release_proof,
        &release_typed,
        &release_venue,
        &release_link,
        &approve(
            &fixture.facility,
            &fixture.authorizer,
            &fixture.nodes,
            order.statement().unwrap(),
            3,
        ),
        1_000,
    )
    .unwrap_err();
    assert!(premature.contains("not expired"));

    let mut stale = order.clone();
    let stale_before = issuer
        .key
        .commit_u64(59, &(source_blinding - reserve_openings.amount));
    stale.refund_leg.before_commitment = stale_before.compress().to_bytes();
    stale.refund_leg.after_commitment = (stale_before + release_typed.payment.amount_commitment)
        .compress()
        .to_bytes();
    let stale_error = release_reservation(
        &fixture.facility,
        &stale,
        &release_proof,
        &release_typed,
        &release_venue,
        &release_link,
        &approve(
            &fixture.facility,
            &fixture.authorizer,
            &fixture.nodes,
            stale.statement().unwrap(),
            3,
        ),
        1_001,
    )
    .unwrap_err();
    assert!(stale_error.contains("stale refund account"));

    let approval = approve(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        order.statement().unwrap(),
        3,
    );
    let receipt = release_reservation(
        &fixture.facility,
        &order,
        &release_proof,
        &release_typed,
        &release_venue,
        &release_link,
        &approval,
        1_001,
    )
    .unwrap();
    assert!(receipt.verify(&fixture.facility.receipt_public_key));
    assert_eq!(
        fixture.facility.account(&source.handle).unwrap().unwrap(),
        (cash.asset_id, source_before.compress().to_bytes(), 2)
    );
    let released = fixture
        .facility
        .credit_facility(&facility_id)
        .unwrap()
        .unwrap();
    assert_eq!(released.available_commitment, cap);
    assert_eq!(released.held_commitment, ZERO);
    assert_eq!(released.sequence, 2);

    let replay = release_reservation(
        &fixture.facility,
        &order,
        &release_proof,
        &release_typed,
        &release_venue,
        &release_link,
        &approval,
        1_002,
    )
    .unwrap();
    assert_eq!(replay.digest().unwrap(), receipt.digest().unwrap());
    assert_eq!(
        fixture.facility.account(&source.handle).unwrap().unwrap().2,
        2
    );
    assert!(fixture.facility.verify_receipt_chain().unwrap());
}

fn product_settlement_for(kind: GuarantorKind) {
    let fixture = credit_fixture_for(kind);
    let security = register(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        "JP0000000001",
        AssetKind::Security,
        0,
    );
    let cash_asset = AssetDefinition {
        asset_id: h("asset:JPY-GUARANTEE"),
        code: "JPY-GUARANTEE".into(),
        kind: AssetKind::Cash,
        decimals: 0,
        terms_digest: h("terms:JPY-GUARANTEE"),
    };
    // Live legal-entity credentials.  The facility beneficiary is the scoped
    // entity commitment, never a wallet or a plaintext corporate identifier.
    let mut kyb_issuer = KybIssuer::new(4, &mut OsRng);
    let attributes = BusinessAttributes {
        jurisdiction: "JP".into(),
        entity_type: "regulated-dealer".into(),
        collateral_tier: 3,
    };
    let maker_credential = kyb_issuer
        .enroll("product-maker-control", attributes.clone(), &mut OsRng)
        .unwrap();
    let taker_credential = kyb_issuer
        .enroll("product-taker-control", attributes, &mut OsRng)
        .unwrap();
    let required_cohort = cohort_id("JP", "regulated-dealer", 2);
    let registry: SignedCohortRegistry = kyb_issuer.publish(&required_cohort, 7, 10_000).unwrap();
    let kyb_scope = b"qomm/product/legal-entity";
    let kyb_context = b"qomm/avalanche/defmi/product-v1";
    let maker_presentation = present(
        &maker_credential,
        &registry,
        kyb_scope,
        kyb_context,
        &mut OsRng,
    )
    .unwrap();
    let taker_presentation = present(
        &taker_credential,
        &registry,
        kyb_scope,
        kyb_context,
        &mut OsRng,
    )
    .unwrap();
    let trusted_issuer = kyb_issuer.public_key();
    let maker_entity = maker_presentation.entity_commitment();
    let taker_entity = taker_presentation.entity_commitment();

    let maker_cap_blinding = Scalar::random(&mut OsRng);
    let maker_cap = credit_commit(100, &maker_cap_blinding);
    let mut maker_grant = CreditFacilityGrant {
        operation_id: h("credit:product-maker-grant"),
        facility_id: h("credit:product-maker-facility"),
        guarantor_id: h("guarantor:ccp-or-bank"),
        beneficiary_commitment: maker_entity,
        rail_asset_id: cash_asset.asset_id,
        cap_commitment: maker_cap,
        available_commitment: maker_cap,
        held_commitment: ZERO,
        outstanding_commitment: ZERO,
        collateral_commitment: credit_commit(150, &Scalar::random(&mut OsRng)),
        risk_policy_digest: h("risk-policy:v1"),
        relation_proof_digest: h("credit:product-maker-grant-proof"),
        valid_from: 1,
        valid_until: 10_000,
        nonce: h("credit:product-maker-grant-nonce"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    maker_grant.guarantor_signature = fixture
        .guarantor
        .sign(&maker_grant.guarantor_message().unwrap());
    fixture
        .facility
        .grant_credit_facility(
            &maker_grant,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                maker_grant.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();

    let taker_cap_blinding = Scalar::random(&mut OsRng);
    let taker_cap = credit_commit(100, &taker_cap_blinding);
    let mut taker_grant = CreditFacilityGrant {
        operation_id: h("credit:product-taker-grant"),
        facility_id: h("credit:product-taker-facility"),
        guarantor_id: h("guarantor:ccp-or-bank"),
        beneficiary_commitment: taker_entity,
        rail_asset_id: security.asset_id,
        cap_commitment: taker_cap,
        available_commitment: taker_cap,
        held_commitment: ZERO,
        outstanding_commitment: ZERO,
        collateral_commitment: credit_commit(150, &Scalar::random(&mut OsRng)),
        risk_policy_digest: h("risk-policy:v1"),
        relation_proof_digest: h("credit:product-taker-grant-proof"),
        valid_from: 1,
        valid_until: 10_000,
        nonce: h("credit:product-taker-grant-nonce"),
        guarantor_signature: Signature::from_bytes(&[0; 64]),
    };
    taker_grant.guarantor_signature = fixture
        .guarantor
        .sign(&taker_grant.guarantor_message().unwrap());
    fixture
        .facility
        .grant_credit_facility(
            &taker_grant,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                taker_grant.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();

    let (secret, public) = deal_quorum(7, 3, &mut OsRng).unwrap();
    let shares: BTreeMap<_, _> = secret
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let maker_handle = RistrettoPoint::mul_base(&Scalar::from(21u64));
    let taker_handle = RistrettoPoint::mul_base(&Scalar::from(22u64));
    let issuer = Issuer::new(Pedersen::new(b"qomm:defmi:v1"), Bounds::default());
    let venue_id = h("venue:qomm");
    let defmi_id = h("defmi:avalanche-local");
    let maker_policy = h("maker-policy:v7");
    let rfq_nullifier = h("rfq:nullifier:product");
    let admission_ticket_id = h("admission-ticket:product");

    // The eventual price is produced and signed by the quorum.  No Maker or
    // Taker signature below contains that exact quote.
    let (payment, settlement_openings) = threshold_settlement_payment(
        &issuer,
        10,
        4,
        security.asset_id,
        maker_handle,
        taker_handle,
        500,
        h("zkpi:product:nonce"),
        h("quote-proof:product"),
        &shares,
        &public,
    );

    // Build the two Reserve zkPIs first; their hidden amount commitments are
    // the exact maxima that the mandates sign and the facility locks.
    let maker_reserve_handle = reserve_handle_for(&maker_grant.facility_id);
    let (maker_reserve_payment_digest, maker_reserve_openings, maker_reserve_partial) = issuer
        .build_for_asset_id(
            40,
            1,
            cash_asset.asset_id,
            maker_handle,
            maker_reserve_handle,
            1_000,
            h("zkpi:maker-reserve:nonce"),
            70,
            &mut OsRng,
        )
        .unwrap();
    let maker_reserve_payment =
        maker_reserve_partial.sealed(frost_sign(&shares, &public, &maker_reserve_payment_digest));
    let taker_reserve_handle = reserve_handle_for(&taker_grant.facility_id);
    let (taker_reserve_payment_digest, taker_reserve_openings, taker_reserve_partial) = issuer
        .build_for_asset_id(
            10,
            1,
            security.asset_id,
            taker_handle,
            taker_reserve_handle,
            1_000,
            h("zkpi:taker-reserve:nonce"),
            71,
            &mut OsRng,
        )
        .unwrap();
    let taker_reserve_payment =
        taker_reserve_partial.sealed(frost_sign(&shares, &public, &taker_reserve_payment_digest));

    let maker_signing_key = SigningKey::generate(&mut OsRng);
    let maker_hold_id = h("product:hold:maker");
    let maker_mandate = MakerPolicyMandate {
        venue_id,
        defmi_id,
        policy_digest: maker_policy,
        policy_version: 7,
        asset_id: cash_asset.asset_id,
        direction: Direction::TakerSells,
        reserve_id: maker_hold_id,
        maximum_amount_commitment: maker_reserve_payment
            .amount_commitment
            .compress()
            .to_bytes(),
        maker_handle: maker_handle.compress().to_bytes(),
        entity_commitment: maker_entity,
        kyb_presentation_digest: maker_presentation.binding_digest(),
        valid_from: 1,
        valid_until: 1_000,
        auto_execute: true,
        maker_public: maker_signing_key.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0; 64]),
    }
    .sign(&maker_signing_key)
    .unwrap();
    let maker_mandate_digest = maker_mandate.digest().unwrap();

    let taker_signing_key = SigningKey::generate(&mut OsRng);
    let taker_hold_id = h("product:hold:taker");
    let taker_mandate = TakerExecutionMandate {
        venue_id,
        defmi_id,
        rfq_nullifier,
        asset_id: security.asset_id,
        reserve_asset_id: security.asset_id,
        direction: Direction::TakerSells,
        quantity_commitment: payment.amount_commitment.compress().to_bytes(),
        limit_price_commitment: payment.price_commitment.compress().to_bytes(),
        maximum_fee_commitment: credit_commit(0, &Scalar::random(&mut OsRng)),
        maximum_amount_commitment: taker_reserve_payment
            .amount_commitment
            .compress()
            .to_bytes(),
        reserve_id: taker_hold_id,
        taker_handle: taker_handle.compress().to_bytes(),
        entity_commitment: taker_entity,
        kyb_presentation_digest: taker_presentation.binding_digest(),
        admission_ticket_id,
        admission_slot: 12,
        fill_mask_commitment: h("product:fill-mask-commitment"),
        deadline: 1_000,
        allow_partial: false,
        auto_settle: true,
        taker_public: taker_signing_key.verifying_key().to_bytes(),
        signature: Signature::from_bytes(&[0; 64]),
    }
    .sign(&taker_signing_key)
    .unwrap();
    let taker_mandate_digest = taker_mandate.digest().unwrap();
    let (admission_committee, admission_plan, admission_lanes) =
        certified_admission_population(AdmissionPopulation {
            label: "product-admission",
            venue_id,
            epoch: 9,
            slot: taker_mandate.admission_slot,
            first_sequence: 1,
            claims: &[h("admission-cover-claim:product"), taker_mandate_digest],
            tickets: &[h("admission-cover-ticket:product"), admission_ticket_id],
            order_digest: h("admission-order:product"),
        });
    let ordered_admission = OrderedAdmission {
        venue_id,
        epoch: admission_plan.epoch,
        slot: taker_mandate.admission_slot,
        sequence: 2,
        ticket_id: admission_ticket_id,
        batch_digest: admission_plan.batch_digest,
        order_digest: admission_plan.order_digest,
        rfq_nullifier,
        taker_entity_commitment: taker_entity,
        taker_mandate_digest,
        expires_at: taker_mandate.deadline,
    };
    let admission_digest = ordered_admission.certified_digest().unwrap();
    assert_eq!(admission_plan.admission_digests[1], admission_digest);
    fixture
        .facility
        .register_admission_committee(
            &admission_committee,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                admission_committee.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    fixture
        .facility
        .register_admission_batch(
            &admission_plan,
            &admission_lanes,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                admission_plan.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    let cover_advance = AdmissionSlotAdvance {
        operation_id: h("admission-cover-operation:product"),
        batch_id: admission_plan.batch_id,
        sequence: 1,
        admission_digest: admission_plan.admission_digests[0],
    };
    let advanced = fixture
        .facility
        .advance_admission_slot(
            &cover_advance,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                cover_advance.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    assert_eq!(advanced.consumed, 1);
    let price_limit_proof = prove_price_limit(
        &issuer.key,
        4,
        &settlement_openings.price,
        4,
        &settlement_openings.price,
        PriceLimitDirection::MinimumSellPrice,
        32,
        &taker_mandate_digest,
    )
    .unwrap();

    // Open the real anonymous source/destination accounts before either
    // reservation.  A reserve now changes these account states immediately;
    // the locked maximum is no longer spendable while the quote is pending.
    let sec_from_handle: [u8; 32] = account_of(&taker_handle, SECURITIES_RAIL)
        .try_into()
        .unwrap();
    let sec_to_handle: [u8; 32] = account_of(&maker_handle, SECURITIES_RAIL)
        .try_into()
        .unwrap();
    let cash_from_handle: [u8; 32] = account_of(&maker_handle, CASH_RAIL).try_into().unwrap();
    let cash_to_handle: [u8; 32] = account_of(&taker_handle, CASH_RAIL).try_into().unwrap();
    let ledger_key = Pedersen::new(b"qomm:defmi:v1");
    let sec_from_blinding = Scalar::random(&mut OsRng);
    let sec_to_blinding = Scalar::random(&mut OsRng);
    let cash_from_blinding = Scalar::random(&mut OsRng);
    let cash_to_blinding = Scalar::random(&mut OsRng);
    let sec_from_before = ledger_key.commit_u64(50, &sec_from_blinding);
    let sec_to_before = ledger_key.commit_u64(0, &sec_to_blinding);
    let cash_from_before = ledger_key.commit_u64(100, &cash_from_blinding);
    let cash_to_before = ledger_key.commit_u64(0, &cash_to_blinding);
    let sec_from = opening_with_handle(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        "product-sec-from",
        sec_from_handle,
        &security,
        sec_from_before.compress().to_bytes(),
    );
    let sec_to = opening_with_handle(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        "product-sec-to",
        sec_to_handle,
        &security,
        sec_to_before.compress().to_bytes(),
    );
    let cash_from = opening_with_handle(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        "product-cash-from",
        cash_from_handle,
        &cash_asset,
        cash_from_before.compress().to_bytes(),
    );
    let cash_to = opening_with_handle(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        "product-cash-to",
        cash_to_handle,
        &cash_asset,
        cash_to_before.compress().to_bytes(),
    );

    let (maker_hold, maker_hold_proof) = bound_hold_transition(
        maker_grant.facility_id,
        "maker",
        maker_policy,
        maker_cap_blinding,
        40,
        maker_reserve_openings.amount,
    );
    assert_eq!(maker_hold.hold_id, maker_hold_id);
    let maker_reserve_context = ExecutionContext {
        operation: OperationKind::Reserve,
        scope: AuthorizationScope::Maker,
        direction: TradeDirection::TakerSells,
        venue_id,
        defmi_id,
        maker_handle,
        taker_handle,
        reserve_handle: maker_reserve_handle,
        maker_reservation_id: maker_hold.hold_id,
        maker_reservation_sequence: 0,
        taker_reservation_id: ZERO,
        taker_reservation_sequence: 0,
        rfq_nullifier: ZERO,
        taker_mandate_digest: ZERO,
        maker_policy_digest: maker_policy,
        maker_mandate_digest,
        maker_reserve_receipt_digest: ZERO,
        taker_reserve_receipt_digest: ZERO,
        quote_proof_digest: ZERO,
        market_statement_digest: ZERO,
        before_state_root: fixture.facility.state_root().unwrap(),
    };
    let maker_reserve_authorization = frost_sign(
        &shares,
        &public,
        &typed_digest_for(
            &maker_reserve_payment,
            &maker_reserve_context,
            DEFAULT_DOMAIN,
        )
        .unwrap(),
    );
    let maker_reserve_typed = TypedInstruction {
        payment: maker_reserve_payment,
        context: maker_reserve_context,
        authorization: maker_reserve_authorization,
    };
    let maker_reserve_link = qomm_defmi::asset_link::prove(
        &issuer.key,
        cash_asset.asset_id,
        &maker_reserve_typed.payment.asset_commitment,
        &maker_reserve_openings.asset,
        &mut OsRng,
    )
    .unwrap();
    let maker_typed_digest: [u8; 32] =
        Sha256::digest(typed_wire::encode(&maker_reserve_typed)).into();
    let maker_escrow_handle: [u8; 32] = account_of(&maker_reserve_handle, CASH_RAIL)
        .try_into()
        .unwrap();
    let mut maker_source_ledger = Ledger::new(ledger_key.clone(), 32);
    maker_source_ledger.open(&cash_from_handle, cash_from_before);
    let (maker_escrow_transfer, _) = maker_source_ledger
        .build_transfer_with_amount_blinding(
            100,
            &cash_from_blinding,
            40,
            &maker_reserve_openings.amount,
            &escrow_transfer_context(&maker_hold.hold_id),
            None,
            &Scalar::ZERO,
            true,
        )
        .unwrap();
    let maker_escrow_proof = ReservationEscrowProof {
        transfer: maker_escrow_transfer,
    };
    let maker_escrow = ReservationEscrow {
        source_handle: cash_from_handle,
        escrow_handle: maker_escrow_handle,
        asset_id: cash_asset.asset_id,
        amount_commitment: maker_reserve_typed
            .payment
            .amount_commitment
            .compress()
            .to_bytes(),
        source_before_commitment: cash_from_before.compress().to_bytes(),
        source_after_commitment: maker_escrow_proof
            .transfer
            .remainder_commitment
            .compress()
            .to_bytes(),
        source_before_sequence: 0,
        proof_digest: maker_escrow_proof.digest(),
    };
    let maker_authorization = ReservationAuthorization {
        role: ReservationRole::Maker,
        entity_commitment: maker_entity,
        asset_id: cash_asset.asset_id,
        direction: 2,
        authorization_digest: maker_policy,
        mandate_digest: maker_mandate_digest,
        typed_reserve_digest: maker_typed_digest,
        reserve_nullifier: maker_reserve_typed.payment.nullifier(),
        asset_link_proof_digest: maker_reserve_link.digest(
            &cash_asset.asset_id,
            &maker_reserve_typed.payment.asset_commitment,
        ),
        limit_price_commitment: ZERO,
        escrow_digest: maker_escrow.statement().unwrap(),
        rfq_nullifier: ZERO,
        policy_version: 7,
        admission_ticket_id: ZERO,
        admission_slot: 0,
        admission_receipt_digest: ZERO,
        admission_epoch: 0,
        admission_sequence: 0,
        admission_batch_id: ZERO,
    };
    let maker_receipt = maker_authorization.statement(&maker_hold).unwrap();
    let maker_identity = IdentityEvidence {
        presentation: &maker_presentation,
        registry: &registry,
        trusted_issuer: &trusted_issuer,
        scope: kyb_scope,
        context: kyb_context,
        required_cohort: &required_cohort,
    };
    let reserve_venue = Venue::new(
        Pedersen::new(b"qomm:defmi:v1"),
        &Bounds::default(),
        public.clone(),
    );
    reserve_maker(
        &fixture.facility,
        &maker_hold,
        &maker_hold_proof,
        &maker_authorization,
        &maker_escrow,
        &maker_escrow_proof,
        &maker_reserve_typed,
        &reserve_venue,
        &maker_reserve_link,
        &maker_mandate,
        &maker_identity,
        &approve(
            &fixture.facility,
            &fixture.authorizer,
            &fixture.nodes,
            maker_receipt,
            3,
        ),
        100,
    )
    .unwrap();

    let (taker_hold, taker_hold_proof) = bound_hold_transition(
        taker_grant.facility_id,
        "taker",
        taker_mandate_digest,
        taker_cap_blinding,
        10,
        taker_reserve_openings.amount,
    );
    assert_eq!(taker_hold.hold_id, taker_hold_id);
    let taker_reserve_context = ExecutionContext {
        operation: OperationKind::Reserve,
        scope: AuthorizationScope::Taker,
        direction: TradeDirection::TakerSells,
        venue_id,
        defmi_id,
        maker_handle,
        taker_handle,
        reserve_handle: taker_reserve_handle,
        maker_reservation_id: ZERO,
        maker_reservation_sequence: 0,
        taker_reservation_id: taker_hold.hold_id,
        taker_reservation_sequence: 0,
        rfq_nullifier,
        taker_mandate_digest,
        maker_policy_digest: ZERO,
        maker_mandate_digest: ZERO,
        maker_reserve_receipt_digest: ZERO,
        taker_reserve_receipt_digest: ZERO,
        quote_proof_digest: ZERO,
        market_statement_digest: ZERO,
        before_state_root: fixture.facility.state_root().unwrap(),
    };
    let taker_reserve_authorization = frost_sign(
        &shares,
        &public,
        &typed_digest_for(
            &taker_reserve_payment,
            &taker_reserve_context,
            DEFAULT_DOMAIN,
        )
        .unwrap(),
    );
    let taker_reserve_typed = TypedInstruction {
        payment: taker_reserve_payment,
        context: taker_reserve_context,
        authorization: taker_reserve_authorization,
    };
    let taker_reserve_link = qomm_defmi::asset_link::prove(
        &issuer.key,
        security.asset_id,
        &taker_reserve_typed.payment.asset_commitment,
        &taker_reserve_openings.asset,
        &mut OsRng,
    )
    .unwrap();
    let taker_typed_digest: [u8; 32] =
        Sha256::digest(typed_wire::encode(&taker_reserve_typed)).into();
    let taker_escrow_handle: [u8; 32] = account_of(&taker_reserve_handle, SECURITIES_RAIL)
        .try_into()
        .unwrap();
    let mut taker_source_ledger = Ledger::new(ledger_key.clone(), 32);
    taker_source_ledger.open(&sec_from_handle, sec_from_before);
    let (taker_escrow_transfer, _) = taker_source_ledger
        .build_transfer_with_amount_blinding(
            50,
            &sec_from_blinding,
            10,
            &taker_reserve_openings.amount,
            &escrow_transfer_context(&taker_hold.hold_id),
            None,
            &Scalar::ZERO,
            true,
        )
        .unwrap();
    let taker_escrow_proof = ReservationEscrowProof {
        transfer: taker_escrow_transfer,
    };
    let taker_escrow = ReservationEscrow {
        source_handle: sec_from_handle,
        escrow_handle: taker_escrow_handle,
        asset_id: security.asset_id,
        amount_commitment: taker_reserve_typed
            .payment
            .amount_commitment
            .compress()
            .to_bytes(),
        source_before_commitment: sec_from_before.compress().to_bytes(),
        source_after_commitment: taker_escrow_proof
            .transfer
            .remainder_commitment
            .compress()
            .to_bytes(),
        source_before_sequence: 0,
        proof_digest: taker_escrow_proof.digest(),
    };
    let taker_authorization = ReservationAuthorization {
        role: ReservationRole::Taker,
        entity_commitment: taker_entity,
        asset_id: security.asset_id,
        direction: 2,
        authorization_digest: taker_mandate_digest,
        mandate_digest: taker_mandate_digest,
        typed_reserve_digest: taker_typed_digest,
        reserve_nullifier: taker_reserve_typed.payment.nullifier(),
        asset_link_proof_digest: taker_reserve_link.digest(
            &security.asset_id,
            &taker_reserve_typed.payment.asset_commitment,
        ),
        limit_price_commitment: taker_mandate.limit_price_commitment,
        escrow_digest: taker_escrow.statement().unwrap(),
        rfq_nullifier,
        policy_version: 0,
        admission_ticket_id,
        admission_slot: ordered_admission.slot,
        admission_receipt_digest: admission_digest,
        admission_epoch: 9,
        admission_sequence: 2,
        admission_batch_id: admission_plan.batch_id,
    };
    let taker_receipt = taker_authorization.statement(&taker_hold).unwrap();
    let taker_identity = IdentityEvidence {
        presentation: &taker_presentation,
        registry: &registry,
        trusted_issuer: &trusted_issuer,
        scope: kyb_scope,
        context: kyb_context,
        required_cohort: &required_cohort,
    };
    reserve_taker(
        &fixture.facility,
        &taker_hold,
        &taker_hold_proof,
        &taker_authorization,
        &taker_escrow,
        &taker_escrow_proof,
        &taker_reserve_typed,
        &reserve_venue,
        &taker_reserve_link,
        &ordered_admission,
        &taker_mandate,
        &taker_identity,
        &approve(
            &fixture.facility,
            &fixture.authorizer,
            &fixture.nodes,
            taker_receipt,
            3,
        ),
        100,
    )
    .unwrap();

    assert_eq!(
        fixture
            .facility
            .account(&cash_from.handle)
            .unwrap()
            .unwrap(),
        (cash_asset.asset_id, maker_escrow.source_after_commitment, 1,)
    );
    assert_eq!(
        fixture.facility.account(&sec_from.handle).unwrap().unwrap(),
        (security.asset_id, taker_escrow.source_after_commitment, 1,)
    );

    // Final DvP spends the locked maxima. Each of the selected nodes contributes
    // only its own price/product and remainder-range shares; the assembler never
    // receives a clear balance, quantity, price, cash value, or blinding.
    let parties = [1usize, 2, 3, 4, 5, 6, 7];
    let quorum = [1usize, 4, 7];
    let cash_blinding = Scalar::random(&mut OsRng);
    let cash_commitment = ledger_key.commit_u64(40, &cash_blinding);
    let price_shares = deal(
        &ledger_key,
        &Scalar::from(4u64),
        &settlement_openings.price,
        &parties,
        2,
        &mut OsRng,
    )
    .unwrap();
    let product_cross = deal(
        &ledger_key,
        &(cash_blinding - settlement_openings.amount * Scalar::from(4u64)),
        &Scalar::ZERO,
        &parties,
        2,
        &mut OsRng,
    )
    .unwrap()
    .value_shares;
    let securities_remainder_blinding = taker_reserve_openings.amount - settlement_openings.amount;
    let cash_remainder_blinding = maker_reserve_openings.amount - cash_blinding;
    let securities_remainder = deal_bits(
        &ledger_key,
        0,
        &securities_remainder_blinding,
        issuer.bounds.amount_bits,
        &parties,
        2,
        &mut OsRng,
    )
    .unwrap();
    let cash_remainder = deal_bits(
        &ledger_key,
        0,
        &cash_remainder_blinding,
        issuer.bounds.amount_bits,
        &parties,
        2,
        &mut OsRng,
    )
    .unwrap();
    let dvp_nodes = parties
        .iter()
        .map(|party| {
            let securities = securities_remainder.node_view(*party).unwrap();
            let cash = cash_remainder.node_view(*party).unwrap();
            MpcDvpNode::new(
                LocalProductShares::new(
                    *party,
                    price_shares.value_shares[party],
                    price_shares.blinding_shares[party],
                    product_cross[party],
                    2,
                )
                .unwrap(),
                LocalRangeShares::new(
                    securities.party,
                    securities.value_share,
                    securities.blinding_share,
                    securities
                        .bits
                        .into_iter()
                        .map(|bit| (bit.bit_share, bit.blinding_share, bit.cross_share))
                        .collect(),
                    2,
                )
                .unwrap(),
                LocalRangeShares::new(
                    cash.party,
                    cash.value_share,
                    cash.blinding_share,
                    cash.bits
                        .into_iter()
                        .map(|bit| (bit.bit_share, bit.blinding_share, bit.cross_share))
                        .collect(),
                    2,
                )
                .unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let dvp_evaluations = dvp_nodes
        .iter()
        .map(|node| node.evaluations(&ledger_key, &payment.amount_commitment))
        .collect::<Vec<_>>();
    let securities_remainder_commitment =
        taker_reserve_typed.payment.amount_commitment - payment.amount_commitment;
    let cash_remainder_commitment = maker_reserve_typed.payment.amount_commitment - cash_commitment;
    let dvp_statements = dvp_statements(
        &payment.amount_commitment,
        &payment.price_commitment,
        &cash_commitment,
        &securities_remainder_commitment,
        &cash_remainder_commitment,
        &dvp_evaluations,
        2,
    )
    .unwrap();
    let bound_dvp_nodes = dvp_nodes
        .into_iter()
        .map(|node| {
            (
                node.party(),
                node.bind(&ledger_key, &dvp_statements).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let dvp_relations = dvp_relation_statements(
        &dvp_statements,
        &bound_dvp_nodes
            .values()
            .map(|node| node.relation_evaluations(&ledger_key))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let mut dvp_seals = Vec::new();
    let mut dvp_secrets = Vec::new();
    let mut dvp_round1 = Vec::new();
    for party in quorum {
        let (seal, secret, first) = bound_dvp_nodes[&party].prepare_round1(
            &ledger_key,
            &payment.amount_commitment,
            &mut OsRng,
        );
        dvp_seals.push(seal);
        dvp_secrets.push((party, secret));
        dvp_round1.push(first);
    }
    let dvp_challenge =
        make_dvp_challenge(&dvp_statements, &dvp_round1, &dvp_seals, &quorum).unwrap();
    let dvp_round2 = dvp_secrets
        .into_iter()
        .map(|(party, secret)| {
            bound_dvp_nodes[&party]
                .answer(secret, &dvp_challenge)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let dvp_proofs = assemble_dvp_proofs(
        &ledger_key,
        &dvp_statements,
        &dvp_relations,
        &dvp_round1,
        &dvp_seals,
        &dvp_round2,
        &quorum,
    )
    .unwrap();
    let dvp_package = build_threshold_package_from_proofs(
        &ledger_key,
        payment.clone(),
        Sides {
            securities_from: taker_escrow_handle.to_vec(),
            securities_to: sec_to_handle.to_vec(),
            cash_from: maker_escrow_handle.to_vec(),
            cash_to: cash_to_handle.to_vec(),
        },
        taker_reserve_typed.payment.amount_commitment,
        maker_reserve_typed.payment.amount_commitment,
        cash_commitment,
        dvp_proofs,
        issuer.bounds.amount_bits,
    )
    .unwrap();

    let quote_proof_digest = h("quote-proof:product");
    let market_statement_digest = h("market:product");
    let context = ExecutionContext {
        operation: OperationKind::Settle,
        scope: AuthorizationScope::Joint,
        direction: TradeDirection::TakerSells,
        venue_id,
        defmi_id,
        maker_handle,
        taker_handle,
        reserve_handle: reserve_handle_for(&h("joint-product-reserve")),
        maker_reservation_id: maker_hold.hold_id,
        maker_reservation_sequence: 1,
        taker_reservation_id: taker_hold.hold_id,
        taker_reservation_sequence: 1,
        rfq_nullifier,
        taker_mandate_digest,
        maker_policy_digest: maker_policy,
        maker_mandate_digest,
        maker_reserve_receipt_digest: maker_receipt,
        taker_reserve_receipt_digest: taker_receipt,
        quote_proof_digest,
        market_statement_digest,
        before_state_root: fixture.facility.state_root().unwrap(),
    };
    let authorization = frost_sign(
        &shares,
        &public,
        &typed_digest_for(&payment, &context, DEFAULT_DOMAIN).unwrap(),
    );
    let typed = TypedInstruction {
        payment,
        context,
        authorization,
    };
    let typed_instruction_digest: [u8; 32] = Sha256::digest(typed_wire::encode(&typed)).into();
    let asset_link = qomm_defmi::asset_link::prove(
        &issuer.key,
        security.asset_id,
        &typed.payment.asset_commitment,
        &settlement_openings.asset,
        &mut OsRng,
    )
    .unwrap();
    let asset_link_proof_digest =
        asset_link.digest(&security.asset_id, &typed.payment.asset_commitment);
    let settlement = SettlementOrder {
        operation_id: h("product:settlement"),
        nullifier: typed.payment.nullifier(),
        deadline: typed.payment.deadline,
        payment_instruction_digest: typed_instruction_digest,
        proof_digest: quote_proof_digest,
        market_statement_digest,
        legs: vec![
            leg(
                &sec_from,
                &security,
                taker_escrow_proof
                    .transfer
                    .remainder_commitment
                    .compress()
                    .to_bytes(),
                (taker_escrow_proof.transfer.remainder_commitment
                    + dvp_package.securities_remainder)
                    .compress()
                    .to_bytes(),
                1,
            ),
            leg(
                &sec_to,
                &security,
                sec_to_before.compress().to_bytes(),
                (sec_to_before + dvp_package.instruction.amount_commitment)
                    .compress()
                    .to_bytes(),
                0,
            ),
            leg(
                &cash_from,
                &cash_asset,
                maker_escrow_proof
                    .transfer
                    .remainder_commitment
                    .compress()
                    .to_bytes(),
                (maker_escrow_proof.transfer.remainder_commitment + dvp_package.cash_remainder)
                    .compress()
                    .to_bytes(),
                1,
            ),
            leg(
                &cash_to,
                &cash_asset,
                cash_to_before.compress().to_bytes(),
                (cash_to_before + dvp_package.cash_commitment)
                    .compress()
                    .to_bytes(),
                0,
            ),
        ],
    };
    let settlement_statement = settlement.statement().unwrap();
    let dvp_digest = dvp_package.digest();
    let maker_before = fixture
        .facility
        .credit_facility(&maker_grant.facility_id)
        .unwrap()
        .unwrap();
    let maker_consume = build_threshold_dvp_consumption(
        h("product:consume-operation:maker"),
        &maker_hold,
        &maker_before,
        ReservationRole::Maker,
        dvp_package.cash_commitment,
        dvp_package.cash_remainder,
        settlement_statement,
        dvp_digest,
    )
    .unwrap();
    let taker_before = fixture
        .facility
        .credit_facility(&taker_grant.facility_id)
        .unwrap()
        .unwrap();
    let taker_consume = build_threshold_dvp_consumption_from_snapshot(
        h("product:consume-operation:taker"),
        &CreditHoldSnapshot::from(&taker_hold),
        &taker_before,
        ReservationRole::Taker,
        dvp_package.instruction.amount_commitment,
        dvp_package.securities_remainder,
        settlement_statement,
        dvp_digest,
    )
    .unwrap();
    let product = ProductSettlementOrder {
        settlement,
        venue_id: typed.context.venue_id,
        defmi_id: typed.context.defmi_id,
        maker_entity_commitment: maker_authorization.entity_commitment,
        taker_entity_commitment: taker_entity,
        rfq_nullifier,
        taker_authorization_digest: taker_mandate_digest,
        maker_policy_digest: maker_policy,
        maker_mandate_digest,
        taker_mandate_digest,
        typed_instruction_digest,
        quote_proof_digest,
        price_limit_proof_digest: price_limit_proof.digest(
            &typed.payment.price_commitment,
            &typed.payment.price_commitment,
            &taker_mandate_digest,
        ),
        dvp_proof_digest: dvp_digest,
        quantity_commitment: dvp_package
            .instruction
            .amount_commitment
            .compress()
            .to_bytes(),
        cash_commitment: dvp_package.cash_commitment.compress().to_bytes(),
        traded_asset_id: security.asset_id,
        asset_link_proof_digest,
        admission_receipt_digest: admission_digest,
        admission_epoch: 9,
        admission_sequence: 2,
        reservations: vec![
            ReservationConsumption {
                role: ReservationRole::Maker,
                reserve_receipt_digest: maker_receipt,
                transition: maker_consume,
            },
            ReservationConsumption {
                role: ReservationRole::Taker,
                reserve_receipt_digest: taker_receipt,
                transition: taker_consume,
            },
        ],
    };
    let approval = approve(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        product.statement().unwrap(),
        3,
    );
    let venue = Venue::new(Pedersen::new(b"qomm:defmi:v1"), &Bounds::default(), public);
    let receipt = settle_product_threshold_authorized(
        &fixture.facility,
        &product,
        &[],
        &typed,
        &venue,
        &asset_link,
        &dvp_package,
        &price_limit_proof,
        &maker_mandate,
        &maker_identity,
        &taker_mandate,
        &taker_identity,
        &approval,
        200,
        &mut OsRng,
    )
    .unwrap();
    assert!(receipt.verify(&fixture.facility.receipt_public_key));
    assert_eq!(
        fixture
            .facility
            .credit_facility(&maker_grant.facility_id)
            .unwrap()
            .unwrap()
            .sequence,
        2
    );
    assert_eq!(
        fixture
            .facility
            .credit_facility(&taker_grant.facility_id)
            .unwrap()
            .unwrap()
            .sequence,
        2
    );
    for (account, expected_sequence) in
        [(&sec_from, 2), (&sec_to, 1), (&cash_from, 2), (&cash_to, 1)]
    {
        assert_eq!(
            fixture
                .facility
                .account(&account.handle)
                .unwrap()
                .unwrap()
                .2,
            expected_sequence
        );
    }
    assert!(fixture.facility.verify_receipt_chain().unwrap());
}

#[test]
fn product_reserve_and_threshold_dvp_support_ccp_bank_credit_provider_and_self_guarantee() {
    for kind in [
        GuarantorKind::CentralCounterparty,
        GuarantorKind::Bank,
        GuarantorKind::CreditProvider,
        GuarantorKind::SelfGuaranteed,
    ] {
        product_settlement_for(kind);
    }
}

#[test]
fn admission_batches_force_every_real_or_cover_lane_through_the_signed_order() {
    let fixture = credit_fixture();
    let (committee, plan, lanes) = certified_admission_population(AdmissionPopulation {
        label: "ordered-batch",
        venue_id: h("ordered-batch:venue"),
        epoch: 17,
        slot: 29,
        first_sequence: 1,
        claims: &[
            h("ordered-batch:claim-1"),
            h("ordered-batch:claim-2"),
            h("ordered-batch:claim-3"),
        ],
        tickets: &[
            h("ordered-batch:ticket-1"),
            h("ordered-batch:ticket-2"),
            h("ordered-batch:ticket-3"),
        ],
        order_digest: h("ordered-batch:order"),
    });
    fixture
        .facility
        .register_admission_committee(
            &committee,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                committee.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    let registered = fixture
        .facility
        .register_admission_batch(
            &plan,
            &lanes,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                plan.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    assert_eq!((registered.population, registered.consumed), (3, 0));

    let second = AdmissionSlotAdvance {
        operation_id: h("ordered-batch:advance-2"),
        batch_id: plan.batch_id,
        sequence: 2,
        admission_digest: plan.admission_digests[1],
    };
    let before_rejection = fixture.facility.state_root().unwrap();
    assert!(fixture
        .facility
        .advance_admission_slot(
            &second,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                second.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap_err()
        .contains("not the next"));
    assert_eq!(fixture.facility.state_root().unwrap(), before_rejection);

    let first = AdmissionSlotAdvance {
        operation_id: h("ordered-batch:advance-1"),
        batch_id: plan.batch_id,
        sequence: 1,
        admission_digest: plan.admission_digests[0],
    };
    let first_approval = approve(
        &fixture.facility,
        &fixture.authorizer,
        &fixture.nodes,
        first.statement().unwrap(),
        3,
    );
    let first_result = fixture
        .facility
        .advance_admission_slot(&first, &first_approval, 100)
        .unwrap();
    assert_eq!(first_result.consumed, 1);
    // Exact retries are idempotent even though their approval names the old
    // state root; a changed body under the same operation id is never accepted.
    assert_eq!(
        fixture
            .facility
            .advance_admission_slot(&first, &first_approval, 100)
            .unwrap()
            .consumed,
        1
    );
    let mut operation_reuse = first.clone();
    operation_reuse.admission_digest = plan.admission_digests[1];
    assert!(fixture
        .facility
        .advance_admission_slot(
            &operation_reuse,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                operation_reuse.statement().unwrap(),
                3,
            ),
            100,
        )
        .is_err());

    let second_result = fixture
        .facility
        .advance_admission_slot(
            &second,
            &approve(
                &fixture.facility,
                &fixture.authorizer,
                &fixture.nodes,
                second.statement().unwrap(),
                3,
            ),
            100,
        )
        .unwrap();
    assert_eq!(second_result.consumed, 2);
}
