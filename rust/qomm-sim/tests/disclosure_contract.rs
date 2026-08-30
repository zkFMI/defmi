use qomm_sim::deterministic_random::DeterministicRng;
use qomm_sim::disclosure::{advanced_composition, discrete_laplace, EntityAccountant};

#[test]
fn exact_discrete_laplace_draws_match_the_locked_vectors() {
    for (epsilon, sensitivity, seed, expected) in [
        (1.0, 1.0, 0, vec![0, 0, -2, 0, 0, 0, 0, 3, 0, 1, -1, -1]),
        (
            0.25,
            3.0,
            1,
            vec![11, 6, -13, 23, -4, -3, -2, 2, 12, -1, 9, -7],
        ),
        (
            0.25,
            300.0,
            11,
            vec![
                -6_136, -1_314, -1_318, -908, 1_664, -1_237, 598, 1_126, 15, 295, -748, -75,
            ],
        ),
        (4.0, 1.0, 7, vec![-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        (64.0, 1.0, 9, vec![0; 12]),
        (130.0, 2.0, 10, vec![0; 12]),
    ] {
        let mut rng = DeterministicRng::new(seed);
        let got: Vec<i64> = (0..expected.len())
            .map(|_| discrete_laplace(epsilon, sensitivity, &mut rng))
            .collect();
        assert_eq!(got, expected, "epsilon={epsilon} sensitivity={sensitivity}");
    }
}

#[test]
fn advanced_composition_and_accounting_match_the_locked_vectors() {
    for (epsilon, releases, delta, expected) in [
        (0.1, 1, 1e-6, 0.536_169_268_783_258),
        (0.25, 40, 1e-6, 11.151_544_848_222_965),
        (1.0, 5, 1e-6, 20.345_349_144_679_226),
        (0.5, 17, 0.0, 8.5),
        (2.0, 3, 1e-9, 60.635_869_726_682_93),
    ] {
        assert!(
            (advanced_composition(epsilon, releases, delta) - expected).abs() < 1e-12,
            "epsilon={epsilon} releases={releases} delta={delta}"
        );
        let mut account = EntityAccountant::with_delta(1_000.0, delta);
        for _ in 0..releases {
            account.spend(epsilon);
        }
        assert_eq!(account.releases, releases);
        assert!(
            (account.spent - expected).abs() < 1e-12,
            "epsilon={epsilon} releases={releases} delta={delta}"
        );
    }
}
