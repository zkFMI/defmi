//! Regression for the 2026-09-07 finding: the linkage of a bit-decomposition
//! range proof pins the residual's value part to zero. Before the fix, honest
//! bits for 44 could be linked to a commitment to 300 with a general opening
//! proof of the residual, and an 8-bit range proof accepted 300.

use curve25519_dalek::scalar::Scalar;
use qomm_zk::bitrange::*;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::prove_opening;
use rand::rngs::OsRng;

#[test]
fn bits_of_another_value_do_not_link() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:zk:test");
    let bits = 8usize;
    let ctx: &[u8] = b"ctx";
    // the commitment under test is to 300, outside [0, 256)
    let r = Scalar::random(&mut rng);
    let big = key.commit_u64(300, &r);
    // honest bit commitments for 44 under fresh blindings
    let small = key.commit_u64(44, &r);
    let mut proof = prove_range(&key, &small, 44, &r, bits, ctx, &mut rng).expect("honest proof");
    // re-prove only the linkage against `big`: residual = big - sum 2^j C_j has
    // value part 300 - 44 = 256 and blinding part r - sum 2^j r_j. The prover
    // cannot know sum 2^j r_j from the proof alone, so recompute it the way a
    // dishonest prover who made the bits would: prove afresh with known blindings.
    // Simplest faithful route: build bits ourselves.
    let bit_blindings: Vec<Scalar> = (0..bits).map(|_| Scalar::random(&mut rng)).collect();
    let mut aggregate_blinding = Scalar::ZERO;
    let mut weight = Scalar::ONE;
    let value_bits: Vec<u64> = (0..bits).map(|j| (44u64 >> j) & 1).collect();
    let mut bit_commitments = Vec::new();
    let mut bit_proofs = Vec::new();
    for (j, (b, rb)) in value_bits.iter().zip(&bit_blindings).enumerate() {
        let c = key.commit_u64(*b, rb);
        let mut t = component_transcript(&bit_context(ctx, j).unwrap());
        bit_proofs.push(qomm_zk::sigma::prove_bit(
            &key,
            &mut t,
            &c,
            *b == 1,
            rb,
            &mut rng,
        ));
        bit_commitments.push(c);
        aggregate_blinding += rb * weight;
        weight += weight;
    }
    let aggregate: curve25519_dalek::ristretto::RistrettoPoint = bit_commitments
        .iter()
        .zip(std::iter::successors(Some(Scalar::ONE), |w| Some(w + w)))
        .map(|(c, w)| c * w)
        .sum();
    let residual = big - aggregate;
    let mut t = component_transcript(&suffixed_context(ctx, b":link"));
    let linkage = prove_opening(
        &key,
        &mut t,
        &residual,
        &Scalar::from(256u64),
        &(r - aggregate_blinding),
        &mut rng,
    );
    proof.bit_commitments = bit_commitments;
    proof.bit_proofs = bit_proofs;
    proof.linkage = linkage;
    assert!(
        !verify_range(&key, &big, &proof, ctx),
        "FORGERY ACCEPTED: 300 passed an 8-bit range proof"
    );
}
