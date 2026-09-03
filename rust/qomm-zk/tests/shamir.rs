//! Naming the party whose share does not lie on the polynomial.
//!
//! The claim being tested is not that Berlekamp--Welch exists --- it is from
//! 1986 --- but that this deployment's parameters put the corruption threshold
//! exactly at the decoding capacity, so the party that lied can be named from
//! what the protocol already sends.
//!
//! The boundary tests matter more than the success ones. A decoder that quietly
//! named an innocent party when three lied would be worse than one that gave up.

use curve25519_dalek::scalar::Scalar;
use qomm_zk::shamir::*;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;

const DEGREE: usize = 2; // T = 2
const PRODUCT_DEGREE: usize = 4; // 2T, a product before degree reduction

fn corrupt(shares: &mut [Scalar], who: &[usize]) {
    let mut rng = OsRng;
    for i in who {
        shares[*i] += Scalar::from(rng.gen_range(1u64..1_000_000));
    }
}

// --- the parameters, which are where everything comes from ---------------

#[test]
fn seven_nodes_at_threshold_two_sit_exactly_at_the_capacity() {
    assert_eq!(
        capacity(7, DEGREE),
        2,
        "and that coincidence is the finding"
    );
}

#[test]
fn a_product_before_degree_reduction_is_one_short_at_seven() {
    assert_eq!(capacity(7, PRODUCT_DEGREE), 1);
    assert_eq!(
        capacity(9, PRODUCT_DEGREE),
        2,
        "which is the entire reason for nine"
    );
}

// --- the honest path ------------------------------------------------------

#[test]
fn an_untouched_sharing_decodes_to_the_secret_and_names_nobody() {
    let mut rng = OsRng;
    let points = points(7);
    for secret in [0u64, 1, 42, 1_000_000] {
        let secret = Scalar::from(secret);
        let shares = share(&secret, DEGREE, &points, &mut rng);
        assert_eq!(reconstruct(&points[..3], &shares[..3]), secret);
        assert_eq!(
            locate(&points, &shares, DEGREE),
            Verdict::Decoded {
                secret,
                culprits: Vec::new()
            }
        );
    }
}

// --- one and two liars ----------------------------------------------------

#[test]
fn one_wrong_share_is_corrected_and_its_sender_named() {
    let mut rng = OsRng;
    let points = points(7);
    let secret = Scalar::from(1234u64);
    for who in 0..7 {
        let mut shares = share(&secret, DEGREE, &points, &mut rng);
        corrupt(&mut shares, &[who]);
        assert_eq!(
            locate(&points, &shares, DEGREE),
            Verdict::Decoded {
                secret,
                culprits: vec![who]
            },
            "party {who}"
        );
    }
}

#[test]
fn two_wrong_shares_are_corrected_and_both_named() {
    let mut rng = OsRng;
    let points = points(7);
    let secret = Scalar::from(99u64);
    for _ in 0..12 {
        let mut who: Vec<usize> = (0..7).collect();
        who.shuffle(&mut rng);
        let mut who = who[..2].to_vec();
        who.sort_unstable();
        let mut shares = share(&secret, DEGREE, &points, &mut rng);
        corrupt(&mut shares, &who);
        assert_eq!(
            locate(&points, &shares, DEGREE),
            Verdict::Decoded {
                secret,
                culprits: who.clone()
            },
            "{who:?}"
        );
    }
}

#[test]
fn three_wrong_shares_are_given_up_on_rather_than_guessed_at() {
    // Naming a party here would be naming one at random, which is worse than
    // giving up --- so the verdict says how many it could have handled.
    let mut rng = OsRng;
    let points = points(7);
    let mut shares = share(&Scalar::from(7u64), DEGREE, &points, &mut rng);
    corrupt(&mut shares, &[0, 3, 5]);
    match locate(&points, &shares, DEGREE) {
        Verdict::Beyond { capacity, reason } => {
            assert_eq!(capacity, 2);
            assert!(reason.contains("beyond what any decoder"), "{reason}");
        }
        other => panic!("named somebody: {other:?}"),
    }
}

#[test]
fn the_decoder_never_names_an_innocent_party() {
    let mut rng = OsRng;
    let points = points(7);
    for _ in 0..40 {
        let count = rng.gen_range(0..=2);
        let mut who: Vec<usize> = (0..7).collect();
        who.shuffle(&mut rng);
        let mut who = who[..count].to_vec();
        who.sort_unstable();
        let secret = Scalar::from(rng.gen_range(1u64..1_000_000));
        let mut shares = share(&secret, DEGREE, &points, &mut rng);
        corrupt(&mut shares, &who);
        assert_eq!(
            locate(&points, &shares, DEGREE),
            Verdict::Decoded {
                secret,
                culprits: who.clone()
            },
            "{who:?}"
        );
    }
}

// --- the product, which is where nine nodes come from --------------------

#[test]
fn a_product_at_nine_nodes_survives_two_liars_and_at_seven_it_does_not() {
    let mut rng = OsRng;
    let secret = Scalar::from(555u64);

    let seven = points(7);
    let mut shares = share(&secret, PRODUCT_DEGREE, &seven, &mut rng);
    corrupt(&mut shares, &[1, 4]);
    assert!(
        matches!(
            locate(&seven, &shares, PRODUCT_DEGREE),
            Verdict::Beyond { .. }
        ),
        "at seven a product corrects one, and this is two"
    );

    let nine = points(9);
    let mut shares = share(&secret, PRODUCT_DEGREE, &nine, &mut rng);
    corrupt(&mut shares, &[1, 4]);
    assert_eq!(
        locate(&nine, &shares, PRODUCT_DEGREE),
        Verdict::Decoded {
            secret,
            culprits: vec![1, 4]
        }
    );
}

#[test]
fn one_missing_node_costs_a_liars_worth_of_capacity() {
    // Eight answering at degree four correct one, not two --- which is what a
    // node dropping out after the inputs actually costs.
    assert_eq!(capacity(9, PRODUCT_DEGREE), 2);
    assert_eq!(capacity(8, PRODUCT_DEGREE), 1);
}

// --- what it cannot see ---------------------------------------------------

#[test]
fn a_consistent_sharing_of_a_different_number_has_nothing_to_decode() {
    // A party that feeds a different value rather than a wrong share is offering
    // a valid sharing of something else. Nothing is inconsistent, so there is
    // nothing here that answers it --- the input check does, and it answers a
    // different question.
    let mut rng = OsRng;
    let points = points(7);
    let elsewhere = Scalar::from(4242u64);
    let shares = share(&elsewhere, DEGREE, &points, &mut rng);
    assert_eq!(
        locate(&points, &shares, DEGREE),
        Verdict::Decoded {
            secret: elsewhere,
            culprits: Vec::new()
        }
    );
}

#[test]
fn too_few_shares_to_determine_the_polynomial_is_refused() {
    let mut rng = OsRng;
    let points = points(2);
    let shares = share(&Scalar::from(3u64), DEGREE, &points, &mut rng);
    assert!(matches!(
        locate(&points, &shares, DEGREE),
        Verdict::Beyond { .. }
    ));
}

#[test]
fn a_mismatched_number_of_points_and_shares_is_refused() {
    let mut rng = OsRng;
    let points = points(7);
    let shares = share(&Scalar::from(3u64), DEGREE, &points, &mut rng);
    assert!(matches!(
        locate(&points, &shares[..5], DEGREE),
        Verdict::Beyond { .. }
    ));
}

/// Past its correction capacity the locator must refuse, not guess.
///
/// A decoder that returns a wrong secret with a confident list of culprits is
/// worse than one that returns nothing: the design's answer to a misbehaving
/// node is to name it and slash its bond, and naming the wrong one is a
/// transfer from an honest party to a dishonest one. So the interesting case is
/// not one or two liars, which it corrects, but three, which it cannot.
#[test]
fn beyond_its_capacity_the_locator_refuses_rather_than_naming_the_wrong_node() {
    let mut rng = OsRng;
    let n = 7usize;
    let degree = 2usize; // T = 2, so capacity is 2
    assert_eq!(capacity(n, degree), 2);

    let secret = Scalar::from(123_456u64);
    let xs = points(n);
    for liars in 1..=4usize {
        let mut ys = share(&secret, degree, &xs, &mut rng);
        // the liars are the last few, so the honest ones are not adjacent by
        // accident in a way that flatters the decoder
        for i in 0..liars {
            ys[n - 1 - i] += Scalar::from(999u64 + i as u64);
        }
        match locate(&xs, &ys, degree) {
            Verdict::Decoded {
                secret: found,
                culprits,
            } => {
                assert!(
                    liars <= capacity(n, degree),
                    "decoded with {liars} liars, past a capacity of {}",
                    capacity(n, degree)
                );
                assert_eq!(found, secret, "decoded the wrong secret");
                let expected: Vec<usize> = (0..liars).map(|i| n - 1 - i).collect();
                let mut named = culprits.clone();
                named.sort_unstable();
                let mut want = expected.clone();
                want.sort_unstable();
                assert_eq!(named, want, "named the wrong nodes");
            }
            Verdict::Beyond { capacity: cap, .. } => {
                assert!(
                    liars > cap,
                    "refused with {liars} liars, inside a capacity of {cap}"
                );
            }
        }
    }
}
