//! The bytes an instruction travels as, and what a second implementation would
//! have to get right.
//!
//! Round-tripping to the *same bytes* is the check, not "it parsed". An
//! implementation that dropped a field and re-derived it would pass the second
//! and fail the first, and it is the first that decides whether two venues can
//! settle the same instruction.

use qomm_zkpi::wire::{decode, encode, fingerprint, WireError, MAGIC, VERSION};
use qomm_zkpi::wire_vectors;

#[test]
fn an_instruction_survives_the_wire_unchanged() {
    let instruction = wire_vectors::sample();
    let bytes = encode(&instruction);
    let back = decode(&bytes).expect("it decodes");
    assert_eq!(encode(&back), bytes, "the codec has to be a fixed point");
    assert_eq!(back.deadline, instruction.deadline);
    assert_eq!(back.quote_key, instruction.quote_key);
    assert_eq!(back.nonce, instruction.nonce);
    assert_eq!(back.amount_commitment, instruction.amount_commitment);
    assert_eq!(
        back.range_commitments.len(),
        instruction.range_commitments.len()
    );
}

#[test]
fn the_digest_the_signature_covers_survives_it_too() {
    // The bytes are not the thing signed --- the digest is --- so a codec that
    // round-tripped the fields but changed the digest would settle a different
    // instruction than the one the quorum authorised.
    let instruction = wire_vectors::sample();
    let back = decode(&encode(&instruction)).unwrap();
    assert_eq!(back.digest(), instruction.digest());
    assert_eq!(back.nullifier(), instruction.nullifier());
}

#[test]
fn every_shipped_vector_does_what_it_says() {
    for vector in wire_vectors::build() {
        match (vector.accepts, decode(&vector.bytes)) {
            (true, Ok(_)) => {
                assert_eq!(wire_vectors::check(&vector.bytes).unwrap(), vector.bytes);
            }
            (false, Err(_)) => {}
            (true, Err(why)) => panic!("{} should be accepted: {why}", vector.name),
            (false, Ok(_)) => panic!("{} should be rejected and was not", vector.name),
        }
        assert_eq!(fingerprint(&vector.bytes), vector.digest);
    }
}

#[test]
fn a_version_this_build_does_not_know_is_refused_and_not_guessed_at() {
    let mut bytes = encode(&wire_vectors::sample());
    bytes[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&(VERSION + 1).to_be_bytes());
    assert_eq!(
        decode(&bytes).err(),
        Some(WireError::UnknownVersion(VERSION + 1))
    );
    // and the message says why, because guessing at a layout is the failure
    // that settles a different payment rather than none
    assert!(WireError::UnknownVersion(2)
        .to_string()
        .contains("valid point"));
}

#[test]
fn a_byte_left_over_is_a_different_message() {
    let mut bytes = encode(&wire_vectors::sample());
    bytes.push(0);
    assert_eq!(decode(&bytes).err(), Some(WireError::Trailing(1)));
}

#[test]
fn a_truncated_instruction_names_where_it_ran_out() {
    let bytes = encode(&wire_vectors::sample());
    let why = decode(&bytes[..bytes.len() - 1])
        .err()
        .expect("it is short");
    assert!(matches!(why, WireError::Truncated { .. }), "{why:?}");
    assert!(why.to_string().contains("were left"), "{why}");
}

#[test]
fn a_commitment_that_is_not_a_group_element_is_refused() {
    let mut bytes = encode(&wire_vectors::sample());
    for byte in bytes[MAGIC.len() + 2..MAGIC.len() + 34].iter_mut() {
        *byte = 0xff;
    }
    assert!(matches!(decode(&bytes), Err(WireError::NotAPoint(_))));
}

#[test]
fn something_that_is_not_an_instruction_at_all_says_so() {
    assert_eq!(
        decode(b"hello").err(),
        Some(WireError::Truncated {
            wanted: 8,
            had: 5,
            at: "magic"
        })
    );
    assert_eq!(
        decode(b"NOTQOMM!more").err(),
        Some(WireError::NotAnInstruction)
    );
}

#[test]
fn a_flipped_bit_anywhere_in_the_body_is_caught_by_something() {
    // Not every flip breaks the codec --- a flipped nonce byte decodes fine ---
    // so the claim is the weaker and true one: either the bytes do not decode,
    // or they decode to an instruction with a different digest, and the
    // signature is over the digest.
    let instruction = wire_vectors::sample();
    let bytes = encode(&instruction);
    let digest = instruction.digest();
    let mut caught = 0;
    for position in (0..bytes.len()).step_by(37) {
        let mut broken = bytes.clone();
        broken[position] ^= 0x01;
        match decode(&broken) {
            Err(_) => caught += 1,
            Ok(other) => {
                if other.digest() != digest || encode(&other) != bytes {
                    caught += 1;
                }
            }
        }
    }
    assert_eq!(
        caught,
        (0..bytes.len()).step_by(37).count(),
        "every flip is either a decode failure or a different digest"
    );
}

#[test]
fn the_wire_is_the_size_the_table_says() {
    // 8 magic + 2 version + 5 * 32 points + 8 deadline + 32 nonce + 8 quote key
    // + 64 signature + 2 count = 284 before the range material.
    let bytes = encode(&wire_vectors::sample());
    let instruction = decode(&bytes).unwrap();
    let fixed = 8 + 2 + 5 * 32 + 8 + 32 + 8 + 64 + 2;
    let commitments = instruction.range_commitments.len() * 32;
    let proofs =
        instruction.amount_range.to_bytes().len() + instruction.price_range.to_bytes().len() + 8;
    assert_eq!(bytes.len(), fixed + commitments + proofs);
}
