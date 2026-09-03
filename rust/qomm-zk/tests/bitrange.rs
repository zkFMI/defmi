//! Fixed and adversarial vectors for the arbitrary-width bit-decomposition
//! range proof.

use curve25519_dalek::scalar::Scalar;
use qomm_zk::bitrange::{prove_bounded, prove_range, verify_bounded, verify_range};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use rand::rngs::StdRng;
use rand::SeedableRng;

const VECTOR_VALUE: u64 = 0x12_3456_789a;
const VECTOR_WIDTH: usize = 40;
const VECTOR_CONTEXT: &[u8] = b"qomm:bitrange:interop:v1";

fn vector_rng() -> StdRng {
    StdRng::from_seed([0x42; 32])
}

#[test]
fn fixed_40_bit_vector_verifies_and_tampering_does_not() {
    let key = Pedersen::new(b"qomm:pedersen:v1");
    let blinding = Scalar::from(0x0fed_cba9_8765_4321u64);
    let commitment = key.commit_u64(VECTOR_VALUE, &blinding);
    let mut rng = vector_rng();
    let proof = prove_range(
        &key,
        &commitment,
        VECTOR_VALUE,
        &blinding,
        VECTOR_WIDTH,
        VECTOR_CONTEXT,
        &mut rng,
    )
    .expect("the fixed value fits 40 bits");

    let honest = verify_range(&key, &commitment, &proof, VECTOR_CONTEXT);
    let wrong_context = verify_range(&key, &commitment, &proof, b"qomm:bitrange:interop:v2");
    let wrong_commitment = key.commit_u64(VECTOR_VALUE + 1, &blinding);
    let wrong_commitment = verify_range(&key, &wrong_commitment, &proof, VECTOR_CONTEXT);
    let mut altered = proof.clone();
    altered.bit_commitments[7] += key.g;
    let tampered_bit = verify_range(&key, &commitment, &altered, VECTOR_CONTEXT);

    println!(
        "rust fixed-vector width={VECTOR_WIDTH} value={VECTOR_VALUE} \
         honest={honest} wrong_context={wrong_context} \
         wrong_commitment={wrong_commitment} tampered_bit={tampered_bit}"
    );
    assert_eq!(proof.bits, VECTOR_WIDTH);
    assert_eq!(proof.bit_commitments.len(), VECTOR_WIDTH);
    assert!(honest);
    assert!(!wrong_context);
    assert!(!wrong_commitment);
    assert!(!tampered_bit);
}

#[test]
fn widths_24_and_40_work_where_bulletproofs_refuses_them() {
    let key = Pedersen::new(b"qomm:pedersen:v1");
    let blinding = Scalar::from(0x1234_5678u64);
    let value = 0x00ab_cdefu64;
    let mut rng = vector_rng();

    for bits in [24, 40] {
        let commitment = key.commit_u64(value, &blinding);
        let proof = prove_range(
            &key,
            &commitment,
            value,
            &blinding,
            bits,
            b"qomm:bitrange:any-width:v1",
            &mut rng,
        )
        .expect("bit decomposition accepts this width");
        assert!(verify_range(
            &key,
            &commitment,
            &proof,
            b"qomm:bitrange:any-width:v1"
        ));
        assert!(std::panic::catch_unwind(|| RangeCtx::new(bits, 1)).is_err());
        println!("rust capability width={bits} bitrange=true bulletproofs=false");
    }
}

#[test]
fn bounded_proof_handles_signed_and_non_power_of_two_intervals() {
    let key = Pedersen::new(b"qomm:pedersen:v1");
    let blinding = Scalar::from(0xfeed_faceu64);
    let mut rng = vector_rng();
    let (commitment, proof, bits) = prove_bounded(
        &key,
        -320,
        &blinding,
        -4_000,
        4_000,
        b"qomm:bounded:vector:v1",
        &mut rng,
    )
    .expect("the value is inside the interval");

    assert_eq!(bits, 13);
    assert!(verify_bounded(
        &key,
        &commitment,
        &proof,
        -4_000,
        4_000,
        b"qomm:bounded:vector:v1"
    ));
    assert!(!verify_bounded(
        &key,
        &commitment,
        &proof,
        -4_000,
        3_999,
        b"qomm:bounded:vector:v1"
    ));
    assert!(prove_bounded(
        &key,
        4_001,
        &blinding,
        -4_000,
        4_000,
        b"qomm:bounded:vector:v1",
        &mut rng,
    )
    .is_err());
}

#[test]
fn out_of_range_values_are_refused() {
    let key = Pedersen::new(b"qomm:pedersen:v1");
    let blinding = Scalar::from(7u64);
    let value = 1u64 << 24;
    let commitment = key.commit_u64(value, &blinding);
    assert!(prove_range(
        &key,
        &commitment,
        value,
        &blinding,
        24,
        b"qomm:bitrange:outside:v1",
        &mut vector_rng(),
    )
    .is_err());
}

/// A bounded proof whose two halves are proved at different widths.
///
/// The outer `bits` field is the one a forger controls; `verify_range` reads
/// each inner proof's own width. Both halves here are honest -- the values and
/// blindings are the real ones, so the linkage holds on both sides -- and the
/// only thing wrong is that the below half is proved one bit wider than the
/// span. If the verifier does not compare the inner widths, the interval it
/// publishes is not the interval it proves.
///
/// The first version of this test built the below half from a witness that did
/// not match its commitment, so the linkage refused it and the assertion held
/// with the width check removed. It tested nothing. This one fails when the
/// width check is taken out.
#[test]
fn a_bounded_proof_cannot_mix_widths_across_its_two_halves() {
    use qomm_zk::bitrange::{shift_commitment, suffixed_context, BoundedProof};
    let key = Pedersen::new(b"qomm:test:bitrange");
    let mut rng = vector_rng();
    let (low, high, value) = (-4000i64, 4000i64, 320i64);
    let span_bits = 13usize; // 8000 needs thirteen

    let blinding = Scalar::random(&mut rng);
    let commitment = key.commit(&Scalar::from(value as u64), &blinding);

    let above = prove_range(
        &key,
        &shift_commitment(&key, &commitment, low),
        (value - low) as u64,
        &blinding,
        span_bits,
        &suffixed_context(b"", b"|above"),
        &mut rng,
    )
    .expect("value - low fits the span");

    // The honest below half, proved one bit wider than the span. Everything
    // about it is correct except the width.
    let ceiling = key.commit(&Scalar::from(high as u64), &Scalar::ZERO);
    let below = prove_range(
        &key,
        &(ceiling - commitment),
        (high - value) as u64,
        &(-blinding),
        span_bits + 1,
        &suffixed_context(b"", b"|below"),
        &mut rng,
    )
    .expect("high - value fits a wider width too");

    let forged = BoundedProof {
        above,
        below,
        bits: span_bits,
    };
    assert!(
        !verify_bounded(&key, &commitment, &forged, low, high, b""),
        "a bounded proof whose halves are proved at different widths was \
         accepted, so the interval it publishes is not the interval it proves"
    );
}
