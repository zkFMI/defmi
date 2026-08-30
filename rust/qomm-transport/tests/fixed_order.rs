use ed25519_dalek::{Signer, SigningKey};
use qomm_transport::order::{
    admission_principal_digest, cluster_batch_digest, decode_execution_attestations,
    encode_execution_attestations, principal_ticket_id, prove_omission, verify_execution_lane,
    AdmissionAuthority, AdmissionTicket, BatchManifest, FixedSlotSealer, NodeExecutionAttestation,
    OrderedAdmission, RandomnessBeacon, ZERO,
};
use qomm_transport::wire::{Frame, FRAME_BYTES, PAYLOAD_BYTES};
use rand_core::OsRng;
use sha2::Digest;

fn frame(slot: u32, node: usize, marker: u8) -> Frame {
    let mut payload = [0u8; PAYLOAD_BYTES];
    payload[0] = marker;
    Frame::new(slot, node, payload, &[b'k'; 32]).unwrap()
}

fn setup(
    population: usize,
) -> (
    AdmissionAuthority,
    Vec<AdmissionTicket>,
    SigningKey,
    FixedSlotSealer,
) {
    let authority_key = SigningKey::generate(&mut OsRng);
    let mut authority = AdmissionAuthority::new(authority_key, vec![b'e'; 32]).unwrap();
    let tickets = (0..population)
        .map(|index| {
            authority
                .issue(
                    format!("lei-{index}").as_bytes(),
                    100,
                    Some(10),
                    1000,
                    Some([index as u8 + 1; 32]),
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    let beacon_key = SigningKey::generate(&mut OsRng);
    let sealer_key = SigningKey::generate(&mut OsRng);
    let sealer = FixedSlotSealer::new(
        100,
        2,
        20_000_000_000,
        tickets.clone(),
        authority.verifying_key(),
        beacon_key.verifying_key(),
        sealer_key,
        ZERO,
    )
    .unwrap();
    (authority, tickets, beacon_key, sealer)
}

#[test]
fn priority_depends_on_preissued_ticket_and_future_beacon_not_payload() {
    let (_, tickets, beacon_key, mut sealer_a) = setup(4);
    let mut sealer_b = FixedSlotSealer::new(
        100,
        2,
        20_000_000_000,
        tickets.clone(),
        sealer_a.authority_key,
        beacon_key.verifying_key(),
        SigningKey::generate(&mut OsRng),
        ZERO,
    )
    .unwrap();
    for (index, ticket) in tickets.iter().enumerate() {
        sealer_a
            .admit(ticket, frame(100, 2, index as u8), 15_000_000_000)
            .unwrap();
        sealer_b
            .admit(ticket, frame(100, 2, 200 - index as u8), 15_000_000_000)
            .unwrap();
    }
    let beacon = RandomnessBeacon::sign(101, [b'b'; 32], &beacon_key);
    let (_, manifest_a) = sealer_a.close(&beacon, 21_000_000_000).unwrap();
    let (_, manifest_b) = sealer_b.close(&beacon, 21_000_000_000).unwrap();
    assert_eq!(
        manifest_a.ordered_ticket_digests,
        manifest_b.ordered_ticket_digests
    );
    assert_ne!(
        manifest_a.ordered_frame_digests,
        manifest_b.ordered_frame_digests
    );
}

#[test]
fn one_legal_entity_cannot_obtain_two_tickets_for_a_slot() {
    let mut authority =
        AdmissionAuthority::new(SigningKey::generate(&mut OsRng), vec![b'e'; 32]).unwrap();
    authority.issue(b"LEI", 7, Some(1), 300, None).unwrap();
    let error = authority.issue(b"LEI", 7, Some(1), 300, None).unwrap_err();
    assert!(error.contains("already"), "{error}");
}

#[test]
fn close_refuses_a_missing_cover_frame_and_late_replacement() {
    let (_, tickets, beacon_key, mut sealer) = setup(2);
    let admitted = frame(100, 2, 1);
    assert_eq!(admitted.encode().len(), FRAME_BYTES);
    // Wire v4 carries fourteen 32-byte field elements: the ten request
    // fields plus Taker product/cash reserve values and blindings.
    assert_eq!(FRAME_BYTES, 495);
    let receipt = sealer.admit(&tickets[0], admitted, 15_000_000_000).unwrap();
    let error = sealer
        .admit(&tickets[0], frame(100, 2, 2), 15_000_000_001)
        .unwrap_err();
    assert!(error.contains("replace"), "{error}");
    let error = sealer
        .close(
            &RandomnessBeacon::sign(101, [b'b'; 32], &beacon_key),
            21_000_000_000,
        )
        .unwrap_err();
    assert!(error.contains("incomplete"), "{error}");
    assert!(receipt.verify(&sealer.verifying_key()));
}

#[test]
fn receipt_proves_omission_without_revealing_the_payload() {
    let (_, tickets, beacon_key, mut sealer) = setup(2);
    let receipts = [
        sealer
            .admit(&tickets[0], frame(100, 2, 1), 15_000_000_000)
            .unwrap(),
        sealer
            .admit(&tickets[1], frame(100, 2, 2), 15_000_000_000)
            .unwrap(),
    ];
    let (_, manifest) = sealer
        .close(
            &RandomnessBeacon::sign(101, [b'b'; 32], &beacon_key),
            21_000_000_000,
        )
        .unwrap();
    let verifying = sealer.verifying_key();
    assert!(manifest.verify(&verifying));
    assert!(!prove_omission(&receipts[0], &manifest, &verifying));

    let kept_tickets = manifest.ordered_ticket_digests[1..].to_vec();
    let kept_frames = manifest.ordered_frame_digests[1..].to_vec();
    let omitted = receipts
        .iter()
        .find(|receipt| !kept_tickets.contains(&receipt.ticket_digest))
        .unwrap();
    let mut forged = BatchManifest {
        slot: manifest.slot,
        node: manifest.node,
        beacon_round: manifest.beacon_round,
        beacon_value: manifest.beacon_value,
        ordered_ticket_digests: kept_tickets,
        ordered_frame_digests: kept_frames,
        previous_digest: manifest.previous_digest,
        signature: ed25519_dalek::Signature::from_bytes(&[0; 64]),
    };
    forged.signature = sealer.signing_key.sign(&forged.unsigned().unwrap());
    assert!(prove_omission(omitted, &forged, &verifying));
}

#[test]
fn ticket_tampering_and_old_beacon_are_rejected() {
    let (_, tickets, beacon_key, mut sealer) = setup(1);
    let mut bad = tickets[0].clone();
    bad.ticket_id = sha2::Sha256::digest(b"bad").into();
    let error = sealer
        .admit(&bad, frame(100, 2, 1), 15_000_000_000)
        .unwrap_err();
    assert!(error.contains("invalid"), "{error}");
    sealer
        .admit(&tickets[0], frame(100, 2, 1), 15_000_000_000)
        .unwrap();
    let error = sealer
        .close(
            &RandomnessBeacon::sign(100, [b'b'; 32], &beacon_key),
            21_000_000_000,
        )
        .unwrap_err();
    assert!(error.contains("after"), "{error}");
}

#[test]
fn seven_node_batch_digest_is_order_independent_but_complete() {
    let mut batches = (0_u16..7)
        .map(|node| (node, [node as u8 + 1; 32]))
        .collect::<Vec<_>>();
    let expected = cluster_batch_digest(9, [8; 32], &batches).unwrap();
    batches.reverse();
    assert_eq!(
        cluster_batch_digest(9, [8; 32], &batches).unwrap(),
        expected
    );
    batches.pop();
    assert!(cluster_batch_digest(9, [8; 32], &batches).is_err());
}

#[test]
fn signed_execution_lane_binds_every_persistence_file_to_the_admitted_batch() {
    let keys = (0..7)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect::<Vec<_>>();
    let mut attestations = keys
        .iter()
        .enumerate()
        .map(|(node, key)| {
            let mut value = NodeExecutionAttestation {
                node: node as u16,
                slot: 9,
                lane: 2,
                batch_digest: [node as u8 + 1; 32],
                source_digest: [8; 32],
                state_generation: 1,
                frame_count: 7,
                input_count: 32,
                stdout_digest: [20 + node as u8; 32],
                stderr_digest: [30 + node as u8; 32],
                persistence_digest: [40 + node as u8; 32],
                receipt_digest: ZERO,
                signature: ed25519_dalek::Signature::from_bytes(&[0; 64]),
            };
            value.receipt_digest = value.recompute_receipt_digest().unwrap();
            value.sign(key).unwrap()
        })
        .collect::<Vec<_>>();
    let trusted = keys
        .iter()
        .map(SigningKey::verifying_key)
        .collect::<Vec<_>>();
    let certified = verify_execution_lane(&attestations, &trusted, [9; 32]).unwrap();
    assert_eq!(certified.slot, 9);
    assert_eq!(certified.lane, 2);

    let encoded = encode_execution_attestations(&attestations).unwrap();
    let decoded = decode_execution_attestations(&encoded).unwrap();
    assert_eq!(
        verify_execution_lane(&decoded, &trusted, [9; 32]).unwrap(),
        certified
    );

    attestations[3].persistence_digest[0] ^= 1;
    assert!(verify_execution_lane(&attestations, &trusted, [9; 32]).is_err());
}

#[test]
fn taker_can_bind_ticket_before_ordered_admission_exists() {
    let principal = "c7f3c553c646cb6f2a0b2e0b3ccf37f1";
    let ticket_id = principal_ticket_id(12, principal).unwrap();
    assert_eq!(ticket_id, principal_ticket_id(12, principal).unwrap());
    assert_ne!(
        admission_principal_digest(principal).unwrap(),
        admission_principal_digest("another-principal").unwrap()
    );
    let admission = OrderedAdmission {
        venue_id: [1; 32],
        epoch: 2,
        slot: 12,
        sequence: 3,
        ticket_id,
        batch_digest: [4; 32],
        order_digest: [8; 32],
        rfq_nullifier: [5; 32],
        taker_entity_commitment: [6; 32],
        taker_mandate_digest: [7; 32],
        expires_at: 100,
    };
    let digest = admission.digest().unwrap();
    let mut moved = admission;
    moved.sequence += 1;
    assert_ne!(moved.digest().unwrap(), digest);
}
