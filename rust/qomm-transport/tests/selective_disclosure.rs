use ed25519_dalek::SigningKey;
use qomm_transport::selective_disclosure::{
    open_if_winner, seal_for_winner, X25519PrivateKey, CLEAR_BYTES,
};
use rand_core::OsRng;

#[test]
fn only_the_winner_opens_a_fixed_size_envelope() {
    let taker = SigningKey::generate(&mut OsRng);
    let winner = X25519PrivateKey::generate().unwrap();
    let loser = X25519PrivateKey::generate().unwrap();
    let quote = [4_u8; 32];
    let envelope = seal_for_winner(
        "maker-7",
        &winner.public_key().unwrap(),
        b"settle instruction",
        b"slot:42",
        quote,
        &taker,
    )
    .unwrap();
    assert_eq!(envelope.ciphertext.len(), CLEAR_BYTES + 16);
    assert_eq!(
        open_if_winner(
            &envelope,
            "maker-7",
            &[loser],
            b"slot:42",
            quote,
            Some(&taker.verifying_key())
        )
        .unwrap(),
        None
    );
    assert_eq!(
        open_if_winner(
            &envelope,
            "maker-7",
            &[winner],
            b"slot:42",
            quote,
            Some(&taker.verifying_key())
        )
        .unwrap(),
        Some(b"settle instruction".to_vec())
    );
}

#[test]
fn public_envelope_does_not_name_the_winner_or_key() {
    let taker = SigningKey::generate(&mut OsRng);
    let winner = X25519PrivateKey::generate().unwrap();
    let public = winner.public_key().unwrap().raw_public_key().unwrap();
    let envelope = seal_for_winner(
        "secret-maker-name",
        &winner.public_key().unwrap(),
        b"x",
        b"market",
        [7; 32],
        &taker,
    )
    .unwrap();
    let unsigned = envelope.unsigned().unwrap();
    assert!(!unsigned
        .windows(b"secret-maker-name".len())
        .any(|part| part == b"secret-maker-name"));
    assert!(!unsigned.windows(public.len()).any(|part| part == public));
}

#[test]
fn context_quote_taker_and_oversize_tampering_are_refused() {
    let taker = SigningKey::generate(&mut OsRng);
    let winner = X25519PrivateKey::generate().unwrap();
    let envelope = seal_for_winner(
        "m",
        &winner.public_key().unwrap(),
        b"x",
        b"market",
        [8; 32],
        &taker,
    )
    .unwrap();
    assert!(open_if_winner(
        &envelope,
        "m",
        std::slice::from_ref(&winner),
        b"other",
        [8; 32],
        None,
    )
    .unwrap_err()
    .contains("context"));
    let stranger = SigningKey::generate(&mut OsRng);
    assert!(open_if_winner(
        &envelope,
        "m",
        &[winner],
        b"market",
        [8; 32],
        Some(&stranger.verifying_key())
    )
    .unwrap_err()
    .contains("signature"));
    assert!(seal_for_winner(
        "m",
        &X25519PrivateKey::generate().unwrap().public_key().unwrap(),
        &vec![0; CLEAR_BYTES],
        b"market",
        [8; 32],
        &taker
    )
    .unwrap_err()
    .contains("exceeds"));
}

#[test]
fn old_private_key_opens_during_rotation_overlap() {
    let taker = SigningKey::generate(&mut OsRng);
    let old = X25519PrivateKey::generate().unwrap();
    let new = X25519PrivateKey::generate().unwrap();
    let envelope = seal_for_winner(
        "m",
        &old.public_key().unwrap(),
        b"rotate",
        b"market",
        [9; 32],
        &taker,
    )
    .unwrap();
    assert_eq!(
        open_if_winner(&envelope, "m", &[new, old], b"market", [9; 32], None).unwrap(),
        Some(b"rotate".to_vec())
    );
}
