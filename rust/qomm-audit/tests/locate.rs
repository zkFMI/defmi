use curve25519_dalek::scalar::Scalar;
use qomm_audit::locate::{capacity, locate, points, reconstruct, share, Verdict};
use rand::rngs::OsRng;

fn corrupt(shares: &mut [Scalar], culprits: &[usize]) {
    for (offset, culprit) in culprits.iter().enumerate() {
        shares[*culprit] += Scalar::from(10_000 + offset as u64);
    }
}

#[test]
fn deployment_capacity_boundaries_match_the_locked_audit() {
    assert_eq!(capacity(7, 2), 2);
    assert_eq!(capacity(7, 4), 1);
    assert_eq!(capacity(5, 2), 1);
    assert_eq!(capacity(4, 2), 0);
    assert_eq!(capacity(3, 2), 0);
    assert_eq!(capacity(10, 2), 3);
}

#[test]
fn every_single_and_pair_of_liars_is_named() {
    let mut rng = OsRng;
    let xs = points(7);
    for first in 0..7 {
        let secret = Scalar::from(100 + first as u64);
        let mut shares = share(&secret, 2, &xs, &mut rng);
        corrupt(&mut shares, &[first]);
        assert_eq!(
            locate(&xs, &shares, 2),
            Verdict::Decoded {
                secret,
                culprits: vec![first]
            }
        );
        for second in (first + 1)..7 {
            let mut shares = share(&secret, 2, &xs, &mut rng);
            corrupt(&mut shares, &[first, second]);
            assert_eq!(
                locate(&xs, &shares, 2),
                Verdict::Decoded {
                    secret,
                    culprits: vec![first, second]
                }
            );
        }
    }
}

#[test]
fn beyond_capacity_is_refused_and_plain_reconstruction_is_silently_wrong() {
    let mut rng = OsRng;
    let xs = points(7);
    let secret = Scalar::from(23_u64);
    let honest = share(&secret, 2, &xs, &mut rng);
    assert_eq!(reconstruct(&xs[..3], &honest[..3]), secret);
    let mut bad = honest;
    corrupt(&mut bad, &[0, 3, 5]);
    let Verdict::Beyond { capacity, reason } = locate(&xs, &bad, 2) else {
        panic!("three liars were guessed at instead of refused");
    };
    assert_eq!(capacity, 2);
    assert!(reason.contains("beyond what any decoder"));
    assert_ne!(reconstruct(&xs[..3], &bad[..3]), secret);
}

#[test]
fn product_shares_use_their_lower_capacity_and_shape_errors_fail_closed() {
    let mut rng = OsRng;
    let xs = points(7);
    let secret = Scalar::from(9_u64);
    let mut one_bad = share(&secret, 4, &xs, &mut rng);
    corrupt(&mut one_bad, &[6]);
    assert_eq!(
        locate(&xs, &one_bad, 4),
        Verdict::Decoded {
            secret,
            culprits: vec![6]
        }
    );
    let mut two_bad = share(&secret, 4, &xs, &mut rng);
    corrupt(&mut two_bad, &[1, 4]);
    assert!(matches!(locate(&xs, &two_bad, 4), Verdict::Beyond { .. }));
    assert!(matches!(
        locate(&xs, &two_bad[..3], 2),
        Verdict::Beyond { .. }
    ));
    let short_points = points(2);
    let short = share(&secret, 2, &short_points, &mut rng);
    assert!(matches!(
        locate(&short_points, &short, 2),
        Verdict::Beyond { .. }
    ));
}
