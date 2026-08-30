use qomm_transport::wire::{
    frame_is_authentic, reconstruct, share_request, FieldElement, Frame, FRAME_BYTES, PAYLOAD_BYTES,
};

const N_REQUEST_VALUES: usize = 4;

const ED25519_ORDER_BE: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

#[test]
fn wire_field_is_exactly_the_mp_spdz_scalar_field() {
    assert!(FieldElement::from_be_bytes(ED25519_ORDER_BE).is_err());
    let mut largest = ED25519_ORDER_BE;
    largest[31] -= 1;
    assert!(FieldElement::from_be_bytes(largest).is_ok());
}

#[test]
fn real_and_cover_requests_have_identical_fixed_wire_size() {
    let real = share_request(&[3, 100, 0, 42], 7).unwrap();
    let cover = share_request(&[0, 0, 0, 0], 7).unwrap();
    assert_eq!(real.len(), 7);
    assert_eq!(cover.len(), 7);
    assert!(real
        .iter()
        .chain(&cover)
        .all(|payload| payload.len() == PAYLOAD_BYTES));
    let key = [7_u8; 32];
    for (node, payload) in real.into_iter().enumerate() {
        let frame = Frame::new(9, node, payload, &key).unwrap();
        assert_eq!(frame.encode().len(), FRAME_BYTES);
        assert_eq!(Frame::decode(&frame.encode()).unwrap(), frame);
        assert!(frame_is_authentic(&key, &frame));
    }
}

#[test]
fn seven_shares_reconstruct_the_request_and_cover_vector() {
    let real = share_request(&[3, 100, 0, 42], 7).unwrap();
    let cover = share_request(&[0, 0, 0, 0], 7).unwrap();
    assert_eq!(
        reconstruct(&real, 4)
            .unwrap()
            .into_iter()
            .map(|value| value.as_u128().unwrap())
            .collect::<Vec<_>>(),
        vec![3, 100, 0, 42]
    );
    assert_eq!(
        reconstruct(&cover, 4)
            .unwrap()
            .into_iter()
            .map(|value| value.as_u128().unwrap())
            .collect::<Vec<_>>(),
        vec![0, 0, 0, 0]
    );
}

#[test]
fn no_share_of_a_real_request_is_the_request() {
    for payload in share_request(&[3, 1_000, 1, 42], 7).unwrap() {
        for index in 0..N_REQUEST_VALUES {
            let value = &payload[index * 32..(index + 1) * 32];
            assert_ne!(&value[..8], &[0_u8; 8]);
        }
    }
}

#[test]
fn the_padding_is_not_a_tell() {
    for values in [[3, 1_000, 1, 42], [0, 0, 0, 0]] {
        for payload in share_request(&values, 7).unwrap() {
            let tail = &payload[N_REQUEST_VALUES * 32..];
            let mut counts = [0_usize; 256];
            for byte in tail {
                counts[usize::from(*byte)] += 1;
            }
            assert!(counts.into_iter().max().unwrap_or(0) < tail.len() / 5);
        }
    }
}

#[test]
fn a_modified_frame_fails_the_mac() {
    let key = [9_u8; 32];
    let payload = share_request(&[1, 2, 3, 4], 2).unwrap().remove(0);
    let frame = Frame::new(1, 0, payload, &key).unwrap();
    let mut raw = frame.encode();
    raw[20] ^= 1;
    assert!(!frame_is_authentic(&key, &Frame::decode(&raw).unwrap()));
}

#[test]
fn a_relay_given_a_key_refuses_a_frame_nobody_signed() {
    let key = [b'k'; 32];
    let payload = share_request(&[3, 1_000, 1, 42], 7).unwrap().remove(0);
    let honest = Frame::new(5, 0, payload, &key).unwrap();
    assert!(frame_is_authentic(&key, &honest));

    let mut forged = honest.clone();
    forged.mac = [0; 32];
    assert!(!frame_is_authentic(&key, &forged));

    let mut moved = honest.clone();
    moved.slot = 6;
    assert!(!frame_is_authentic(&key, &moved));

    let mut other = honest;
    other.node = 1;
    assert!(!frame_is_authentic(&key, &other));
}
