//! One-out-of-many: the set says nothing about which member was used.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::oneofmany::{challenge_for, prove, verify};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

fn set(
    key: &Pedersen,
    size: usize,
    index: usize,
    rng: &mut OsRng,
) -> (Vec<RistrettoPoint>, Scalar) {
    let randomness = Scalar::random(rng);
    let commitments = (0..size)
        .map(|i| {
            if i == index {
                key.commit(&Scalar::ZERO, &randomness)
            } else {
                key.commit(&Scalar::random(rng), &Scalar::random(rng))
            }
        })
        .collect();
    (commitments, randomness)
}

#[test]
fn a_member_that_opens_to_zero_can_be_proved_from_any_position() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:gk:v1");
    for size in [2usize, 4, 8, 16] {
        for index in 0..size {
            let (commitments, randomness) = set(&key, size, index, &mut rng);
            let proof = prove(
                &key,
                &mut Transcript::new(b"t"),
                &commitments,
                index,
                &randomness,
                &mut rng,
            )
            .expect("prove");
            assert!(
                verify(&key, &mut Transcript::new(b"t"), &commitments, &proof),
                "size {size} index {index}"
            );
        }
    }
}

#[test]
fn the_proof_does_not_vary_with_the_hidden_position() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:gk:v1");
    let mut sizes = std::collections::HashSet::new();
    for index in 0..8 {
        let (commitments, randomness) = set(&key, 8, index, &mut rng);
        let proof = prove(
            &key,
            &mut Transcript::new(b"t"),
            &commitments,
            index,
            &randomness,
            &mut rng,
        )
        .unwrap();
        assert!(verify(
            &key,
            &mut Transcript::new(b"t"),
            &commitments,
            &proof
        ));
        sizes.insert(proof.size_bytes());
    }
    assert_eq!(sizes.len(), 1, "the hidden position leaks through the size");
}

#[test]
fn a_set_with_no_zero_member_cannot_be_proved() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:gk:v1");
    let (mut commitments, randomness) = set(&key, 8, 3, &mut rng);
    let proof = prove(
        &key,
        &mut Transcript::new(b"t"),
        &commitments,
        3,
        &randomness,
        &mut rng,
    )
    .unwrap();
    commitments[3] = key.commit(&Scalar::from(1u64), &randomness);
    assert!(!verify(
        &key,
        &mut Transcript::new(b"t"),
        &commitments,
        &proof
    ));
}

#[test]
fn a_proof_does_not_carry_over_to_another_set() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:gk:v1");
    let (commitments, randomness) = set(&key, 8, 2, &mut rng);
    let proof = prove(
        &key,
        &mut Transcript::new(b"t"),
        &commitments,
        2,
        &randomness,
        &mut rng,
    )
    .unwrap();
    let (other, _) = set(&key, 8, 2, &mut rng);
    assert!(!verify(&key, &mut Transcript::new(b"t"), &other, &proof));
    assert!(!verify(
        &key,
        &mut Transcript::new(b"u"),
        &commitments,
        &proof
    ));
}

#[test]
fn the_set_has_to_be_a_power_of_two() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:gk:v1");
    let (commitments, randomness) = set(&key, 8, 0, &mut rng);
    assert!(prove(
        &key,
        &mut Transcript::new(b"t"),
        &commitments[..6],
        0,
        &randomness,
        &mut rng
    )
    .is_err());
    assert!(prove(
        &key,
        &mut Transcript::new(b"t"),
        &commitments,
        9,
        &randomness,
        &mut rng
    )
    .is_err());
}

/// The public set can be altered after the fact, unless the caller binds it.
///
/// The Fiat--Shamir challenge covers `cl`, `ca`, `cb` and `gk` and not the
/// commitments, and the commitments enter only through the final weighted sum
/// `sum_i p_i(x) C_i`. So move mass between two members and leave the sum where
/// it was: pick j and k with `p_k != 0`, add `D` to `C_j` and subtract
/// `(p_j/p_k) D` from `C_k`. The challenge does not move, the sum does not
/// move, and a proof made about the original set verifies against a set the
/// prover has no witness in.
///
/// This is why `oneofmany` absorbs the set itself rather than trusting each
/// caller to remember to.
#[test]
fn the_set_cannot_be_altered_after_the_proof_is_made() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"set-binding");
    let size = 8usize;
    let index = 3usize;
    let blinding = Scalar::random(&mut rng);
    let mut commitments: Vec<RistrettoPoint> = (0..size)
        .map(|_| key.commit(&Scalar::random(&mut rng), &Scalar::random(&mut rng)))
        .collect();
    commitments[index] = key.commit(&Scalar::ZERO, &blinding);

    let proof = prove(
        &key,
        &mut Transcript::new(b"t"),
        &commitments,
        index,
        &blinding,
        &mut rng,
    )
    .unwrap();
    assert!(verify(
        &key,
        &mut Transcript::new(b"t"),
        &commitments,
        &proof
    ));

    // The verifier's own coefficients, recomputed from the proof.
    let x = {
        // the challenge is a function of the proof alone, so re-deriving it
        // needs nothing the attacker does not have
        let mut probe = Transcript::new(b"t");
        challenge_for(&mut probe, &commitments, &proof)
    };
    let bits = size.trailing_zeros() as usize;
    let weight = |i: usize| -> Scalar {
        (0..bits).fold(Scalar::ONE, |acc, j| {
            acc * if (i >> j) & 1 == 1 {
                proof.f[j]
            } else {
                x - proof.f[j]
            }
        })
    };

    let (j, k) = (0usize, 1usize);
    let shift = key.commit(&Scalar::from(99u64), &Scalar::random(&mut rng));
    let mut altered = commitments.clone();
    altered[j] += shift;
    altered[k] -= shift * (weight(j) * weight(k).invert());
    assert_ne!(
        altered, commitments,
        "the alteration must actually change the set"
    );

    assert!(
        !verify(&key, &mut Transcript::new(b"t"), &altered, &proof),
        "a proof about one set verified against another: the challenge does \
             not cover the commitments"
    );
}
