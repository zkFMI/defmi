#![cfg(feature = "avalanche")]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey};
use qomm_defmi::note_chain::{
    escrow_claim_serial, materialize_claim, note_claim_recipient_commitment, note_ring_root,
    verify_claim_materialization, CsdIssuerDefinition, DelegatedNoteSettlementOrder,
    EscrowClaimSpend, NoteClaim, NoteClaimKind, NoteIssuance, NoteOutput, NoteSettlementOrder,
    NoteSpend,
};
use qomm_defmi::notes::{NoteLedger, Wallet};
use qomm_proofs::opening_envelope::{
    encrypt_opening_share, opening_context, EncryptedOpeningShare, OpeningEnvelope,
};
use qomm_proofs::threshold_sigma::deal;
use qomm_zk::pedersen::Pedersen;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

fn id(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn claim(label: &str, asset: [u8; 32], hold: [u8; 32], kind: NoteClaimKind) -> NoteClaim {
    let mut value = NoteClaim {
        claim_id: [0; 32],
        asset_id: asset,
        value_commitment: id(&format!("{label}:value")),
        recipient_commitment: id(&format!("{label}:recipient")),
        source_hold_id: hold,
        kind,
        opening_envelope: OpeningEnvelope::new(
            id(&format!("{label}:opening-context")),
            3,
            G,
            (1..=3)
                .map(|party| EncryptedOpeningShare {
                    party,
                    ephemeral: G,
                    masked_value: Scalar::from(party as u64),
                    masked_blinding: Scalar::from(party as u64 + 10),
                })
                .collect(),
        )
        .unwrap(),
    };
    value.claim_id = value.derived_id().unwrap();
    value
}

#[test]
fn exact_reserve_accepts_a_zero_refund_but_not_a_zero_delivery() {
    let asset = id("zero-refund-asset");
    let hold = id("zero-refund-hold");

    let mut refund = claim("zero-refund", asset, hold, NoteClaimKind::Refund);
    refund.value_commitment = [0; 32];
    refund.claim_id = refund.derived_id().unwrap();
    refund.validate().unwrap();

    let mut delivery = claim("zero-delivery", asset, hold, NoteClaimKind::Delivery);
    delivery.value_commitment = [0; 32];
    delivery.claim_id = delivery.derived_id().unwrap();
    assert_eq!(
        delivery.validate().unwrap_err(),
        "note claim delivery commitment cannot be zero"
    );
}

fn expected(value: [u8; 32], encoded: &str) {
    assert_eq!(hex::encode(value), encoded);
}

#[test]
fn note_issuance_must_be_signed_during_csd_validity() {
    let asset = id("csd-validity-asset");
    let issuer_key = SigningKey::from_bytes(&id("csd-validity-key"));
    let issuer = CsdIssuerDefinition {
        issuer_id: id("csd-validity-issuer"),
        code: "DEFMI-JP-CSD".into(),
        jurisdiction: "JP".into(),
        operator_entity_commitment: id("csd-validity-operator"),
        public_key: issuer_key.verifying_key().to_bytes(),
        permitted_asset_ids: vec![asset],
        policy_digest: id("csd-validity-policy"),
        valid_from: 100,
        valid_until: 1_000,
    };
    let mut output = NoteOutput {
        note_id: [0; 32],
        asset_id: asset,
        one_time: id("csd-validity-one-time"),
        value_commitment: id("csd-validity-value"),
        ephemeral: id("csd-validity-ephemeral"),
        masked_value: id("csd-validity-masked-value"),
        masked_blinding: id("csd-validity-masked-blinding"),
        lock_id: [0; 32],
    };
    output.note_id = output.derived_id().unwrap();
    let issuance = |issued_at| {
        NoteIssuance {
            operation_id: id("csd-validity-operation"),
            issuance_nonce: id("csd-validity-nonce"),
            issuer_id: issuer.issuer_id,
            issued_at,
            output: output.clone(),
            proof_digest: id("csd-validity-proof"),
            issuer_signature: Signature::from_bytes(&[0; 64]),
        }
        .sign_issuer(&issuer_key)
        .unwrap()
    };
    assert!(issuance(99).verify_issuer(&issuer, 100).is_err());
    issuance(100).verify_issuer(&issuer, 100).unwrap();
}

#[test]
fn account_free_consensus_timestamps_fit_sqlites_signed_integer_domain() {
    let max = i64::MAX as u64;
    let overflow = max + 1;
    let asset = id("timestamp-note-asset");
    let issuer_key = SigningKey::from_bytes(&id("timestamp-note-issuer-key"));
    let mut issuer = CsdIssuerDefinition {
        issuer_id: id("timestamp-note-issuer"),
        code: "DEFMI-CSD".into(),
        jurisdiction: "JP".into(),
        operator_entity_commitment: id("timestamp-note-operator"),
        public_key: issuer_key.verifying_key().to_bytes(),
        permitted_asset_ids: vec![asset],
        policy_digest: id("timestamp-note-policy"),
        valid_from: 1,
        valid_until: max,
    };
    issuer.body().unwrap();
    issuer.valid_until = overflow;
    assert!(issuer.body().is_err());

    let mut output = NoteOutput {
        note_id: [0; 32],
        asset_id: asset,
        one_time: id("timestamp-note-one-time"),
        value_commitment: id("timestamp-note-value"),
        ephemeral: id("timestamp-note-ephemeral"),
        masked_value: id("timestamp-note-masked-value"),
        masked_blinding: id("timestamp-note-masked-blinding"),
        lock_id: [0; 32],
    };
    output.note_id = output.derived_id().unwrap();
    let issuance = |issued_at| NoteIssuance {
        operation_id: id("timestamp-note-issuance-operation"),
        issuance_nonce: id("timestamp-note-issuance-nonce"),
        issuer_id: id("timestamp-note-issuer"),
        issued_at,
        output: output.clone(),
        proof_digest: id("timestamp-note-issuance-proof"),
        issuer_signature: Signature::from_bytes(&[0; 64]),
    };
    issuance(max).issuer_message().unwrap();
    assert!(issuance(overflow).issuer_message().is_err());

    let mut second = output.clone();
    second.one_time = id("timestamp-note-second-one-time");
    second.note_id = second.derived_id().unwrap();
    let ring = vec![output.note_id, second.note_id];
    let ring_root = note_ring_root(asset, &ring).unwrap();
    let mut spend_output = output;
    spend_output.one_time = id("timestamp-note-output-one-time");
    spend_output.note_id = spend_output.derived_id().unwrap();
    let note_settlement = |deadline| NoteSettlementOrder {
        operation_id: id("timestamp-note-settlement-operation"),
        nullifier: id("timestamp-note-settlement-nullifier"),
        deadline,
        payment_instruction_digest: id("timestamp-note-zkpi"),
        market_statement_digest: id("timestamp-note-market"),
        dvp_proof_digest: id("timestamp-note-dvp"),
        spends: vec![NoteSpend {
            asset_id: asset,
            ring: ring.clone(),
            ring_root,
            serial_point: id("timestamp-note-serial"),
            input_lock_id: [0; 32],
            proof_digest: id("timestamp-note-spend-proof"),
            outputs: vec![spend_output.clone()],
        }],
        consolidated_output: None,
    };
    note_settlement(max).body().unwrap();
    assert!(note_settlement(overflow).body().is_err());

    let delegated = |deadline| DelegatedNoteSettlementOrder {
        operation_id: id("timestamp-delegated-operation"),
        nullifier: id("timestamp-delegated-nullifier"),
        deadline,
        payment_instruction_digest: id("timestamp-delegated-zkpi"),
        market_statement_digest: id("timestamp-delegated-market"),
        dvp_proof_digest: id("timestamp-delegated-dvp"),
        spends: vec![
            EscrowClaimSpend {
                asset_id: id("timestamp-delegated-security"),
                hold_id: id("timestamp-delegated-security-hold"),
                escrow_note_id: id("timestamp-delegated-security-escrow"),
                delegation_digest: id("timestamp-delegated-security-delegation"),
                proof_digest: id("timestamp-delegated-security-proof"),
                claims: vec![
                    claim(
                        "timestamp-delegated-security-delivery",
                        id("timestamp-delegated-security"),
                        id("timestamp-delegated-security-hold"),
                        NoteClaimKind::Delivery,
                    ),
                    claim(
                        "timestamp-delegated-security-refund",
                        id("timestamp-delegated-security"),
                        id("timestamp-delegated-security-hold"),
                        NoteClaimKind::Refund,
                    ),
                ],
            },
            EscrowClaimSpend {
                asset_id: id("timestamp-delegated-cash"),
                hold_id: id("timestamp-delegated-cash-hold"),
                escrow_note_id: id("timestamp-delegated-cash-escrow"),
                delegation_digest: id("timestamp-delegated-cash-delegation"),
                proof_digest: id("timestamp-delegated-cash-proof"),
                claims: vec![
                    claim(
                        "timestamp-delegated-cash-delivery",
                        id("timestamp-delegated-cash"),
                        id("timestamp-delegated-cash-hold"),
                        NoteClaimKind::Delivery,
                    ),
                    claim(
                        "timestamp-delegated-cash-refund",
                        id("timestamp-delegated-cash"),
                        id("timestamp-delegated-cash-hold"),
                        NoteClaimKind::Refund,
                    ),
                ],
            },
        ],
    };
    delegated(max).body().unwrap();
    assert!(delegated(overflow).body().is_err());
}

#[test]
fn note_consolidation_preserves_the_exact_commitment_sum() {
    let asset = id("note-consolidation-asset");
    let output = |label: &str, value_commitment: [u8; 32]| {
        let mut output = NoteOutput {
            note_id: [0; 32],
            asset_id: asset,
            one_time: id(&format!("{label}:one-time")),
            value_commitment,
            ephemeral: id(&format!("{label}:ephemeral")),
            masked_value: id(&format!("{label}:masked-value")),
            masked_blinding: id(&format!("{label}:masked-blinding")),
            lock_id: [0; 32],
        };
        output.note_id = output.derived_id().unwrap();
        output
    };
    let ring = vec![
        id("note-consolidation-ring-a"),
        id("note-consolidation-ring-b"),
    ];
    let first_output = output(
        "note-consolidation-first",
        (G * Scalar::from(11_u64)).compress().to_bytes(),
    );
    let second_output = output(
        "note-consolidation-second",
        (G * Scalar::from(29_u64)).compress().to_bytes(),
    );
    let spends = vec![
        NoteSpend {
            asset_id: asset,
            ring: ring.clone(),
            ring_root: note_ring_root(asset, &ring).unwrap(),
            serial_point: (G * Scalar::from(41_u64)).compress().to_bytes(),
            input_lock_id: [0; 32],
            proof_digest: id("note-consolidation-first-proof"),
            outputs: vec![first_output],
        },
        NoteSpend {
            asset_id: asset,
            ring: ring.clone(),
            ring_root: note_ring_root(asset, &ring).unwrap(),
            serial_point: (G * Scalar::from(43_u64)).compress().to_bytes(),
            input_lock_id: [0; 32],
            proof_digest: id("note-consolidation-second-proof"),
            outputs: vec![second_output],
        },
    ];
    let final_output = output(
        "note-consolidation-final",
        (G * Scalar::from(40_u64)).compress().to_bytes(),
    );
    let order = NoteSettlementOrder {
        operation_id: id("note-consolidation-operation"),
        nullifier: id("note-consolidation-nullifier"),
        deadline: 999,
        payment_instruction_digest: id("note-consolidation-instruction"),
        market_statement_digest: id("note-consolidation-market"),
        dvp_proof_digest: id("note-consolidation-proof"),
        spends,
        consolidated_output: Some(final_output),
    };
    let body = order.body().unwrap();
    assert!(body.get("consolidated_output").is_some());

    let mut wrong = order;
    wrong.consolidated_output = Some(output(
        "note-consolidation-wrong",
        (G * Scalar::from(39_u64)).compress().to_bytes(),
    ));
    assert!(wrong
        .body()
        .unwrap_err()
        .contains("changes the committed value"));
}

#[test]
fn account_free_note_statements_match_the_pinned_consensus_vectors() {
    let asset = id("note-compat-asset");
    let mut output = NoteOutput {
        note_id: [0; 32],
        asset_id: asset,
        one_time: id("note-compat-one-time"),
        value_commitment: id("note-compat-value"),
        ephemeral: id("note-compat-ephemeral"),
        masked_value: id("note-compat-masked-value"),
        masked_blinding: id("note-compat-masked-blinding"),
        lock_id: [0; 32],
    };
    output.note_id = output.derived_id().unwrap();
    expected(
        output.note_id,
        "f1e2ec40c854dec248fe3319da8097751bb9f587452745edcebafe84eae3d8ab",
    );

    let issuer_seed: [u8; 32] = Sha256::digest(b"note-compat-csd-key").into();
    let issuance = NoteIssuance {
        operation_id: id("note-compat-issue-op"),
        issuance_nonce: id("note-compat-nonce"),
        issuer_id: id("note-compat-csd-issuer"),
        issued_at: 100,
        output: output.clone(),
        proof_digest: id("note-compat-issue-proof"),
        issuer_signature: Signature::from_bytes(&[0_u8; 64]),
    }
    .sign_issuer(&SigningKey::from_bytes(&issuer_seed))
    .unwrap();
    expected(
        issuance.statement().unwrap(),
        "78bac959a69c58db9dea37c290fafa9aab3e108ebee93734b8047e46705b93d3",
    );

    let mut second = output.clone();
    second.one_time = id("note-compat-second-one-time");
    second.note_id = second.derived_id().unwrap();
    let ring = vec![output.note_id, second.note_id];
    let ring_root = note_ring_root(asset, &ring).unwrap();
    expected(
        ring_root,
        "c0e8cec5676b1ba5fdad377f7d55eafb5075a57d849ab051b4c226169e8aeb86",
    );

    let mut spend_output = output;
    spend_output.one_time = id("note-compat-output-one-time");
    spend_output.note_id = spend_output.derived_id().unwrap();
    let settlement = NoteSettlementOrder {
        operation_id: id("note-compat-settle-op"),
        nullifier: id("note-compat-nullifier"),
        deadline: 999,
        payment_instruction_digest: id("note-compat-zkpi"),
        market_statement_digest: id("note-compat-market"),
        dvp_proof_digest: id("note-compat-dvp"),
        spends: vec![NoteSpend {
            asset_id: asset,
            ring,
            ring_root,
            serial_point: id("note-compat-serial"),
            input_lock_id: [0; 32],
            proof_digest: id("note-compat-spend-proof"),
            outputs: vec![spend_output],
        }],
        consolidated_output: None,
    };
    expected(
        settlement.statement().unwrap(),
        "b5c76c5f996f58591c21a84342f6b8441b1a4fc63b6fdb5fb2eb4e5828715ac1",
    );
}

#[test]
fn delegated_claim_statements_match_the_pinned_consensus_vectors() {
    let securities = id("delegated-compat-securities");
    let cash = id("delegated-compat-cash");
    let securities_hold = id("delegated-compat-securities-hold");
    let cash_hold = id("delegated-compat-cash-hold");
    let securities_escrow = id("delegated-compat-securities-escrow");
    let cash_escrow = id("delegated-compat-cash-escrow");
    let securities_delivery = claim(
        "delegated-compat-securities-delivery",
        securities,
        securities_hold,
        NoteClaimKind::Delivery,
    );
    let securities_refund = claim(
        "delegated-compat-securities-refund",
        securities,
        securities_hold,
        NoteClaimKind::Refund,
    );
    let cash_delivery = claim(
        "delegated-compat-cash-delivery",
        cash,
        cash_hold,
        NoteClaimKind::Delivery,
    );
    let cash_refund = claim(
        "delegated-compat-cash-refund",
        cash,
        cash_hold,
        NoteClaimKind::Refund,
    );
    let settlement = DelegatedNoteSettlementOrder {
        operation_id: id("delegated-compat-operation"),
        nullifier: id("delegated-compat-nullifier"),
        deadline: 1_234,
        payment_instruction_digest: id("delegated-compat-zkpi"),
        market_statement_digest: id("delegated-compat-market"),
        dvp_proof_digest: id("delegated-compat-dvp"),
        spends: vec![
            EscrowClaimSpend {
                asset_id: securities,
                hold_id: securities_hold,
                escrow_note_id: securities_escrow,
                delegation_digest: id("delegated-compat-securities-delegation"),
                proof_digest: id("delegated-compat-dvp"),
                claims: vec![securities_delivery.clone(), securities_refund.clone()],
            },
            EscrowClaimSpend {
                asset_id: cash,
                hold_id: cash_hold,
                escrow_note_id: cash_escrow,
                delegation_digest: id("delegated-compat-cash-delegation"),
                proof_digest: id("delegated-compat-dvp"),
                claims: vec![cash_delivery.clone(), cash_refund.clone()],
            },
        ],
    };
    expected(
        securities_delivery.claim_id,
        "302dedeb517545e88811906e8f2cbba09a9605e883eda56ac3addab761a1f589",
    );
    expected(
        cash_delivery.claim_id,
        "0957d6e0ec9aa2f4ac69be5a52bb9fed2c0730c1b23d00d213387e87da624747",
    );
    expected(
        settlement.statement().unwrap(),
        "b0e8377e44d4e802928c0ffb7744e46344ec3f79a07cdc5a432cbfe5536899d8",
    );
    expected(
        escrow_claim_serial(securities_escrow, securities_hold),
        "a097d8d43bfc7a734acfcd9de267054615d50bb7f24c3db6209d47a9314c9ce4",
    );
}

#[test]
fn recipient_recovers_and_materializes_a_final_claim_without_revealing_its_opening() {
    let key = Pedersen::new(b"claim-materialization-test");
    let recipient_secret = Scalar::from(77_u64);
    let recipient_handle = G * recipient_secret;
    let destination = Wallet::new(&mut OsRng);
    let amount = 41_u64;
    let blinding = Scalar::from(91_u64);
    let parties = (1..=7).collect::<Vec<_>>();
    let shared = deal(
        &key,
        &Scalar::from(amount),
        &blinding,
        &parties,
        2,
        &mut OsRng,
    )
    .unwrap();
    let job_id = id("materialize-job");
    let context = opening_context(&job_id, "cash_delivery").unwrap();
    let envelope = OpeningEnvelope::new(
        context,
        3,
        recipient_handle,
        parties
            .iter()
            .map(|party| {
                encrypt_opening_share(
                    context,
                    *party,
                    shared.value_shares[party],
                    shared.blinding_shares[party],
                    &recipient_handle,
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let asset = id("materialize-asset");
    let hold = id("materialize-hold");
    let rfq = id("materialize-rfq");
    let mut claim = NoteClaim {
        claim_id: [0; 32],
        asset_id: asset,
        value_commitment: key.commit_u64(amount, &blinding).compress().to_bytes(),
        recipient_commitment: note_claim_recipient_commitment(
            recipient_handle.compress().to_bytes(),
            rfq,
            asset,
            hold,
            NoteClaimKind::Delivery,
        )
        .unwrap(),
        source_hold_id: hold,
        kind: NoteClaimKind::Delivery,
        opening_envelope: envelope,
    };
    claim.claim_id = claim.derived_id().unwrap();

    let (materialization, proof) = materialize_claim(
        &claim,
        &key,
        8,
        rfq,
        &recipient_secret,
        &destination.address,
        &[1, 4, 7],
        id("materialize-operation"),
        &mut OsRng,
    )
    .unwrap();
    verify_claim_materialization(
        &claim,
        rfq,
        &recipient_handle,
        &destination.address,
        &materialization,
        &proof,
    )
    .unwrap();
    let mut ledger = NoteLedger::new(key.clone(), 8);
    ledger.add(materialization.output.to_note().unwrap());
    let found = ledger.scan(&destination, &key);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1.value, amount);
    assert_eq!(found[0].1.blinding, blinding);
    assert!(materialize_claim(
        &claim,
        &key,
        8,
        rfq,
        &Scalar::from(78_u64),
        &destination.address,
        &[1, 4, 7],
        id("wrong-recipient-operation"),
        &mut OsRng,
    )
    .is_err());
}
