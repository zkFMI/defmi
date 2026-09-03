use ed25519_dalek::{Signer, SigningKey};
use qomm_defmi::cross_domain::{
    derive_leg_id, hash_release_witness, Committee, CommitteeMember, CrossDomainBook,
    CrossDomainError, Domain, FinalityContext, FinalityReceipt, LegStatus, PrepareLeg,
    ReceiptEvent, ReceiptSignature,
};

fn domain(marker: u8) -> Domain {
    Domain {
        network_id: 5,
        chain_id: [marker; 32],
        defmi_id: [marker.wrapping_add(64); 32],
    }
}

fn committee(domain: Domain, marker: u8, epoch: u64) -> (Committee, Vec<SigningKey>) {
    let keys = vec![
        SigningKey::from_bytes(&[marker; 32]),
        SigningKey::from_bytes(&[marker.wrapping_add(1); 32]),
        SigningKey::from_bytes(&[marker.wrapping_add(2); 32]),
    ];
    let members = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let member_id = [marker.wrapping_add(index as u8); 32];
            (
                member_id,
                CommitteeMember {
                    member_id,
                    public_key: key.verifying_key().to_bytes(),
                    weight: 1,
                },
            )
        })
        .map(|(_, member)| member)
        .collect::<Vec<_>>();
    (
        Committee {
            domain,
            epoch,
            quorum_weight: 2,
            members,
        },
        keys,
    )
}

fn sign(
    mut receipt: FinalityReceipt,
    committee: &Committee,
    keys: &[SigningKey],
) -> FinalityReceipt {
    let digest = receipt.signing_digest();
    receipt.signatures = committee
        .members
        .iter()
        .map(|member| &member.member_id)
        .zip(keys.iter())
        .take(2)
        .map(|(member_id, key)| ReceiptSignature {
            member_id: *member_id,
            signature: key.sign(&digest).to_bytes().to_vec(),
        })
        .collect();
    receipt
}

struct Pair {
    a_domain: Domain,
    b_domain: Domain,
    a_id: [u8; 32],
    b_id: [u8; 32],
    a_book: CrossDomainBook,
    b_book: CrossDomainBook,
    a_committee: Committee,
    b_committee: Committee,
    a_keys: Vec<SigningKey>,
    b_keys: Vec<SigningKey>,
    witness: Vec<u8>,
}

fn prepared_pair() -> Pair {
    let a_domain = domain(1);
    let b_domain = domain(2);
    let secret = [99u8; 32];
    let a_id = derive_leg_id(&secret, &a_domain, 0);
    let b_id = derive_leg_id(&secret, &b_domain, 1);
    let witness = b"private adaptor release witness".to_vec();
    let release_condition = hash_release_witness(&witness);
    let a_prepare = PrepareLeg {
        local_domain: a_domain.clone(),
        remote_domain: b_domain.clone(),
        local_leg_id: a_id,
        expected_remote_prepare_binding: [70; 32],
        expected_remote_claim_binding: [71; 32],
        owner_commitment: [11; 32],
        escrow_commitment: [9; 32],
        destination_commitment: [8; 32],
        asset_commitment: [12; 32],
        amount_commitment: [13; 32],
        local_instruction_digest: [14; 32],
        local_relation_proof_digest: [15; 32],
        reserve_transfer_digest: [16; 32],
        claim_transfer_digest: [17; 32],
        refund_transfer_digest: [18; 32],
        arm_deadline: 20,
        claim_deadline: 30,
        refund_after: 40,
        release_condition,
    };
    let b_prepare = PrepareLeg {
        local_domain: b_domain.clone(),
        remote_domain: a_domain.clone(),
        local_leg_id: b_id,
        expected_remote_prepare_binding: [72; 32],
        expected_remote_claim_binding: [73; 32],
        owner_commitment: [21; 32],
        escrow_commitment: [19; 32],
        destination_commitment: [18; 32],
        asset_commitment: [22; 32],
        amount_commitment: [23; 32],
        local_instruction_digest: [27; 32],
        local_relation_proof_digest: [28; 32],
        reserve_transfer_digest: [24; 32],
        claim_transfer_digest: [25; 32],
        refund_transfer_digest: [26; 32],
        arm_deadline: 20,
        claim_deadline: 30,
        refund_after: 40,
        release_condition,
    };
    let (a_committee, a_keys) = committee(a_domain.clone(), 10, 7);
    let (b_committee, b_keys) = committee(b_domain.clone(), 20, 9);
    let mut a_book = CrossDomainBook::default();
    let mut b_book = CrossDomainBook::default();
    a_book.prepare(a_prepare, 10).unwrap();
    b_book.prepare(b_prepare, 11).unwrap();
    Pair {
        a_domain,
        b_domain,
        a_id,
        b_id,
        a_book,
        b_book,
        a_committee,
        b_committee,
        a_keys,
        b_keys,
        witness,
    }
}

fn prepared_receipts(pair: &Pair) -> (FinalityReceipt, FinalityReceipt) {
    let from_a = pair
        .a_book
        .receipt_for(
            pair.a_id,
            ReceiptEvent::Prepared,
            FinalityContext {
                destination_domain: pair.b_domain.clone(),
                destination_leg_id: pair.b_id,
                event_binding: [72; 32],
                source_state_root: [31; 32],
                source_block_id: [41; 32],
                source_height: 101,
                finalised_at: 12,
                validator_epoch: pair.a_committee.epoch,
            },
        )
        .unwrap();
    let from_b = pair
        .b_book
        .receipt_for(
            pair.b_id,
            ReceiptEvent::Prepared,
            FinalityContext {
                destination_domain: pair.a_domain.clone(),
                destination_leg_id: pair.a_id,
                event_binding: [70; 32],
                source_state_root: [32; 32],
                source_block_id: [42; 32],
                source_height: 202,
                finalised_at: 13,
                validator_epoch: pair.b_committee.epoch,
            },
        )
        .unwrap();
    (
        sign(from_a, &pair.a_committee, &pair.a_keys),
        sign(from_b, &pair.b_committee, &pair.b_keys),
    )
}

#[test]
fn completes_across_two_independent_books_and_records_only_local_ids() {
    let mut pair = prepared_pair();
    assert_ne!(pair.a_id, pair.b_id);
    let (from_a, from_b) = prepared_receipts(&pair);

    pair.a_book
        .arm(pair.a_id, &from_b, &pair.b_committee, 14)
        .unwrap();
    pair.b_book
        .arm(pair.b_id, &from_a, &pair.a_committee, 14)
        .unwrap();
    pair.a_book.claim(pair.a_id, &pair.witness, 15).unwrap();
    pair.b_book.claim(pair.b_id, &pair.witness, 16).unwrap();

    assert_eq!(pair.a_book.legs[&pair.a_id].status, LegStatus::Claimed);
    assert_eq!(pair.b_book.legs[&pair.b_id].status, LegStatus::Claimed);
    assert!(!pair.a_book.legs.contains_key(&pair.b_id));
    assert!(!pair.b_book.legs.contains_key(&pair.a_id));
}

#[test]
fn rejects_replay_wrong_order_and_wrong_destination() {
    let mut pair = prepared_pair();
    let (from_a, from_b) = prepared_receipts(&pair);
    pair.a_book
        .arm(pair.a_id, &from_b, &pair.b_committee, 14)
        .unwrap();
    assert_eq!(
        pair.a_book
            .arm(pair.a_id, &from_b, &pair.b_committee, 15)
            .unwrap_err(),
        CrossDomainError::ReceiptAlreadyConsumed
    );

    let mut fresh = prepared_pair();
    let mut wrong = from_a;
    wrong.destination_domain = domain(88);
    wrong.signatures.clear();
    let wrong = sign(wrong, &fresh.a_committee, &fresh.a_keys);
    assert_eq!(
        fresh
            .b_book
            .arm(fresh.b_id, &wrong, &fresh.a_committee, 14)
            .unwrap_err(),
        CrossDomainError::WrongReceiptBinding
    );

    assert_eq!(
        fresh
            .a_book
            .claim(fresh.a_id, &fresh.witness, 14)
            .unwrap_err(),
        CrossDomainError::InvalidTransition
    );
}

#[test]
fn rejects_bad_quorum_epoch_signature_and_release_witness() {
    let mut pair = prepared_pair();
    let (_, from_b) = prepared_receipts(&pair);

    let mut one_signature = from_b.clone();
    one_signature.signatures.truncate(1);
    assert_eq!(
        pair.a_book
            .arm(pair.a_id, &one_signature, &pair.b_committee, 14)
            .unwrap_err(),
        CrossDomainError::InsufficientQuorum
    );

    let mut wrong_epoch = from_b.clone();
    wrong_epoch.validator_epoch += 1;
    assert_eq!(
        pair.a_book
            .arm(pair.a_id, &wrong_epoch, &pair.b_committee, 14)
            .unwrap_err(),
        CrossDomainError::WrongCommittee
    );

    let mut tampered = from_b.clone();
    tampered.source_state_root[0] ^= 1;
    assert_eq!(
        pair.a_book
            .arm(pair.a_id, &tampered, &pair.b_committee, 14)
            .unwrap_err(),
        CrossDomainError::InvalidSignature
    );

    pair.a_book
        .arm(pair.a_id, &from_b, &pair.b_committee, 14)
        .unwrap();
    assert_eq!(
        pair.a_book.claim(pair.a_id, b"wrong", 15).unwrap_err(),
        CrossDomainError::InvalidReleaseWitness
    );
}

#[test]
fn split_or_delayed_delivery_refunds_deterministically() {
    let mut pair = prepared_pair();
    let (_, from_b) = prepared_receipts(&pair);

    assert_eq!(
        pair.a_book
            .arm(pair.a_id, &from_b, &pair.b_committee, 21)
            .unwrap_err(),
        CrossDomainError::ArmDeadlinePassed
    );
    assert_eq!(
        pair.a_book.refund(pair.a_id, 39).unwrap_err(),
        CrossDomainError::RefundTooEarly
    );
    pair.a_book.refund(pair.a_id, 40).unwrap();
    pair.b_book.refund(pair.b_id, 40).unwrap();
    assert_eq!(pair.a_book.legs[&pair.a_id].status, LegStatus::Refunded);
    assert_eq!(pair.b_book.legs[&pair.b_id].status, LegStatus::Refunded);
}

#[test]
fn armed_leg_cannot_refund_and_remains_claimable_after_the_operational_deadline() {
    let mut pair = prepared_pair();
    let (_, from_b) = prepared_receipts(&pair);
    pair.a_book
        .arm(pair.a_id, &from_b, &pair.b_committee, 14)
        .unwrap();
    assert_eq!(
        pair.a_book.refund(pair.a_id, 40).unwrap_err(),
        CrossDomainError::InvalidTransition
    );
    pair.a_book.claim(pair.a_id, &pair.witness, 400).unwrap();
    assert_eq!(pair.a_book.legs[&pair.a_id].status, LegStatus::Claimed);
}

#[test]
fn observes_remote_claim_once_and_rejects_future_receipt() {
    let mut pair = prepared_pair();
    let (from_a, from_b) = prepared_receipts(&pair);
    pair.a_book
        .arm(pair.a_id, &from_b, &pair.b_committee, 14)
        .unwrap();
    pair.b_book
        .arm(pair.b_id, &from_a, &pair.a_committee, 14)
        .unwrap();
    pair.a_book.claim(pair.a_id, &pair.witness, 15).unwrap();
    pair.b_book.claim(pair.b_id, &pair.witness, 15).unwrap();

    let claim_from_b = pair
        .b_book
        .receipt_for(
            pair.b_id,
            ReceiptEvent::Claimed,
            FinalityContext {
                destination_domain: pair.a_domain.clone(),
                destination_leg_id: pair.a_id,
                event_binding: [71; 32],
                source_state_root: [44; 32],
                source_block_id: [45; 32],
                source_height: 203,
                finalised_at: 16,
                validator_epoch: pair.b_committee.epoch,
            },
        )
        .unwrap();
    let claim_from_b = sign(claim_from_b, &pair.b_committee, &pair.b_keys);
    assert_eq!(
        pair.a_book
            .observe_remote_claim(pair.a_id, &claim_from_b, &pair.b_committee, 15)
            .unwrap_err(),
        CrossDomainError::ReceiptOutsideWindow
    );
    pair.a_book
        .observe_remote_claim(pair.a_id, &claim_from_b, &pair.b_committee, 16)
        .unwrap();
    assert_eq!(
        pair.a_book
            .observe_remote_claim(pair.a_id, &claim_from_b, &pair.b_committee, 17)
            .unwrap_err(),
        CrossDomainError::ReceiptAlreadyConsumed
    );
}

#[test]
fn prepare_with_missing_private_event_binding_never_enters_state() {
    let pair = prepared_pair();
    let mut book = CrossDomainBook::default();
    let mut malformed = pair.a_book.legs[&pair.a_id].prepare.clone();
    malformed.expected_remote_prepare_binding = [0; 32];
    assert_eq!(
        book.prepare(malformed, 1).unwrap_err(),
        CrossDomainError::MissingCommitment
    );
    assert!(book.legs.is_empty());
}
