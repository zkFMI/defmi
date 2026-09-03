//! Intraday credit and the waterfall that catches what it does not cover.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::credit::*;
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

fn key() -> Pedersen {
    Pedersen::new(b"qomm:defmi:v1")
}

#[test]
fn a_cap_covered_by_collateral_is_underwritten() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let line = ctx
        .grant(
            b"p0",
            "securities",
            8_000_000,
            &Scalar::random(&mut rng),
            10_000_000,
            &Scalar::random(&mut rng),
            500,
        )
        .unwrap();
    assert_eq!(ctx.check(&line), Ok(()));
}

#[test]
fn a_cap_the_collateral_does_not_support_is_refused() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    assert_eq!(
        ctx.grant(
            b"p0",
            "cash",
            10_000_000,
            &Scalar::random(&mut rng),
            10_000_000,
            &Scalar::random(&mut rng),
            500
        )
        .err(),
        Some("the pledged collateral does not cover the cap")
    );
}

#[test]
fn a_backing_proof_from_another_line_does_not_transfer() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let mut line = ctx
        .grant(
            b"p0",
            "cash",
            8_000_000,
            &Scalar::random(&mut rng),
            10_000_000,
            &Scalar::random(&mut rng),
            500,
        )
        .unwrap();
    let other = ctx
        .grant(
            b"p1",
            "cash",
            1_000,
            &Scalar::random(&mut rng),
            10_000_000,
            &Scalar::random(&mut rng),
            500,
        )
        .unwrap();
    line.backing = other.backing;
    line.backing_commitment = other.backing_commitment;
    assert!(ctx.check(&line).is_err());
}

fn waterfall(rng: &mut OsRng, balances: &[u64]) -> (Waterfall, Vec<Scalar>) {
    let k = key();
    let blindings: Vec<Scalar> = balances.iter().map(|_| Scalar::random(rng)).collect();
    let names = [
        "defaulter collateral",
        "defaulter fund share",
        "FMI capital",
        "surviving members",
    ];
    let tranches = balances
        .iter()
        .zip(blindings.iter())
        .enumerate()
        .map(|(i, (b, r))| Tranche {
            name: names.get(i).unwrap_or(&"further").to_string(),
            commitment: k.commit_u64(*b, r),
        })
        .collect();
    (Waterfall::new(k, tranches, 32), blindings)
}

#[test]
fn the_waterfall_consumes_tranches_in_order() {
    let mut rng = OsRng;
    let balances = [300u64, 200, 500, 5_000];
    let (wf, blindings) = waterfall(&mut rng, &balances);
    for (shortfall, expected) in [
        (250u64, vec![250u64, 0, 0, 0]),
        (700, vec![300, 200, 200, 0]),
        (1_200, vec![300, 200, 500, 200]),
    ] {
        let (resolution, amounts) = wf
            .build(
                shortfall,
                &Scalar::random(&mut rng),
                &balances,
                &blindings,
                &mut rng,
            )
            .unwrap();
        assert_eq!(amounts, expected);
        assert_eq!(wf.check(&resolution, &mut rng), Ok(()));
    }
}

#[test]
fn a_shortfall_larger_than_the_waterfall_is_refused() {
    let mut rng = OsRng;
    let balances = [300u64, 200, 500, 5_000];
    let (wf, blindings) = waterfall(&mut rng, &balances);
    assert_eq!(
        wf.build(
            99_999,
            &Scalar::random(&mut rng),
            &balances,
            &blindings,
            &mut rng
        )
        .err(),
        Some("the shortfall exceeds what the waterfall holds")
    );
}

#[test]
fn skipping_a_tranche_is_caught_by_the_ordering_proof() {
    // the real attack: draw from below while the layer above still has money
    use qomm_zk::sigma::prove_product;
    let mut rng = OsRng;
    let balances = [300u64, 200, 500, 5_000];
    let (wf, blindings) = waterfall(&mut rng, &balances);
    let k = key();
    let shortfall = 200u64;
    let shortfall_blinding = Scalar::random(&mut rng);

    let mut draws = Vec::new();
    for (index, (balance, blinding)) in balances.iter().zip(blindings.iter()).enumerate() {
        let amount = if index == 1 { shortfall } else { 0 };
        let amount_blinding = if index == 1 {
            shortfall_blinding
        } else {
            Scalar::ZERO
        };
        let left = balance - amount;
        let left_blinding = blinding - amount_blinding;
        let mut t = merlin::Transcript::new(b"qomm:waterfall:within");
        t.append_u64(b"k", index as u64);
        let (within, commitments) = bulletproofs::RangeProof::prove_multiple(
            &bulletproofs::BulletproofGens::new(32, 1),
            &bulletproofs::PedersenGens {
                B: k.g,
                B_blinding: k.h,
            },
            &mut t,
            &[left],
            &[left_blinding],
            32,
        )
        .unwrap();
        let ordering = if index == 0 {
            None
        } else {
            let above_value = balances[index - 1] - if index - 1 == 1 { shortfall } else { 0 };
            let above_blinding = blindings[index - 1];
            let mut t = merlin::Transcript::new(b"qomm:waterfall:order");
            t.append_u64(b"k", index as u64);
            Some(prove_product(
                &k,
                &mut t,
                &k.commit_u64(above_value, &above_blinding),
                &Scalar::from(above_value),
                &above_blinding,
                &Scalar::from(amount),
                &amount_blinding,
                &Scalar::ZERO,
                &mut rng,
            ))
        };
        draws.push(Draw {
            tranche: index,
            amount_commitment: k.commit_u64(amount, &amount_blinding),
            within,
            within_commitment: commitments[0],
            ordering,
        });
    }
    let residual = k.commit_u64(shortfall, &shortfall_blinding)
        - draws
            .iter()
            .map(|d| d.amount_commitment)
            .sum::<RistrettoPoint>();
    let mut t = merlin::Transcript::new(b"qomm:waterfall:balance");
    let balance = qomm_zk::sigma::prove_opening(
        &k,
        &mut t,
        &residual,
        &Scalar::ZERO,
        &Scalar::ZERO,
        &mut rng,
    );
    let mut st = merlin::Transcript::new(b"qomm:waterfall:shortfall");
    let (shortfall_range, sc) = bulletproofs::RangeProof::prove_multiple(
        &bulletproofs::BulletproofGens::new(32, 1),
        &bulletproofs::PedersenGens {
            B: k.g,
            B_blinding: k.h,
        },
        &mut st,
        &[shortfall],
        &[shortfall_blinding],
        32,
    )
    .unwrap();
    let forged = Resolution {
        shortfall_commitment: k.commit_u64(shortfall, &shortfall_blinding),
        shortfall_range,
        shortfall_range_commitment: sc[0],
        draws,
        balance,
    };
    assert!(wf.check(&forged, &mut rng).is_err());
}

#[test]
fn the_tranches_after_a_resolution_are_still_commitments() {
    let mut rng = OsRng;
    let balances = [300u64, 200, 500, 5_000];
    let (wf, blindings) = waterfall(&mut rng, &balances);
    let (resolution, amounts) = wf
        .build(
            700,
            &Scalar::random(&mut rng),
            &balances,
            &blindings,
            &mut rng,
        )
        .unwrap();
    let after = wf.applied(&resolution);
    for ((tranche, before), draw) in after
        .iter()
        .zip(wf.tranches.iter())
        .zip(resolution.draws.iter())
    {
        assert_eq!(
            tranche.commitment,
            before.commitment - draw.amount_commitment
        );
    }
    assert_eq!(amounts.iter().sum::<u64>(), 700);
}

// --- collateral that is a security rather than an amount ------------------

use qomm_defmi::credit::{resolution_id, TrancheBook};

/// The price a quorum signed, standing in for an instruction's commitment.
fn signed_price(ctx: &CreditCtx, price: u64, blinding: &Scalar) -> RistrettoPoint {
    ctx.key.commit_u64(price, blinding)
}

#[test]
fn a_pledge_is_valued_at_a_price_the_member_did_not_choose() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let (q, qb) = (400u64, Scalar::random(&mut rng));
    let (p, pb) = (25_000u64, Scalar::random(&mut rng));
    let vb = Scalar::random(&mut rng);
    let quoted = signed_price(&ctx, p, &pb);

    let (pledge, value) = ctx
        .value_pledge(q, &qb, p, &pb, &vb, &quoted, &mut rng)
        .unwrap();
    assert_eq!(value, 10_000_000);
    assert_eq!(ctx.check_pledge(&pledge, &quoted), Ok(()));
}

#[test]
fn a_member_cannot_value_its_pledge_at_a_price_no_quorum_signed() {
    // The whole reason this type exists: collateral already valued means a
    // member underwriting itself.
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let (p, pb) = (25_000u64, Scalar::random(&mut rng));
    let quoted = signed_price(&ctx, p, &pb);
    // it tries a better price
    assert_eq!(
        ctx.value_pledge(
            400,
            &Scalar::random(&mut rng),
            p * 2,
            &pb,
            &Scalar::random(&mut rng),
            &quoted,
            &mut rng
        )
        .err(),
        Some("that is not the price the quorum signed")
    );
}

#[test]
fn a_valuation_moved_to_another_price_is_refused() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let (p, pb) = (25_000u64, Scalar::random(&mut rng));
    let quoted = signed_price(&ctx, p, &pb);
    let (pledge, _) = ctx
        .value_pledge(
            400,
            &Scalar::random(&mut rng),
            p,
            &pb,
            &Scalar::random(&mut rng),
            &quoted,
            &mut rng,
        )
        .unwrap();
    let elsewhere = signed_price(&ctx, p + 1, &pb);
    assert!(ctx.check_pledge(&pledge, &elsewhere).is_err());
}

#[test]
fn a_line_granted_against_a_valued_pledge_underwrites_the_same_way() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let (q, qb) = (400u64, Scalar::random(&mut rng));
    let (p, pb) = (25_000u64, Scalar::random(&mut rng));
    let vb = Scalar::random(&mut rng);
    let quoted = signed_price(&ctx, p, &pb);
    let (pledge, value) = ctx
        .value_pledge(q, &qb, p, &pb, &vb, &quoted, &mut rng)
        .unwrap();

    let cap_blinding = Scalar::random(&mut rng);
    let line = ctx
        .grant_against(
            b"p0",
            "cash",
            8_000_000,
            &cap_blinding,
            &pledge,
            value,
            &vb,
            500,
            &quoted,
        )
        .unwrap();
    assert_eq!(ctx.check(&line), Ok(()));

    // and a cap the valuation does not support is refused downstream, the same
    // way it would be for cash
    assert!(ctx
        .grant_against(
            b"p0",
            "cash",
            9_999_999,
            &cap_blinding,
            &pledge,
            value,
            &vb,
            500,
            &quoted
        )
        .is_err());
}

#[test]
fn an_opening_that_is_not_the_value_that_was_proved_is_refused() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(key(), 64);
    let (p, pb) = (25_000u64, Scalar::random(&mut rng));
    let vb = Scalar::random(&mut rng);
    let quoted = signed_price(&ctx, p, &pb);
    let (pledge, value) = ctx
        .value_pledge(
            400,
            &Scalar::random(&mut rng),
            p,
            &pb,
            &vb,
            &quoted,
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        ctx.grant_against(
            b"p0",
            "cash",
            1_000,
            &Scalar::random(&mut rng),
            &pledge,
            value + 1,
            &vb,
            500,
            &quoted
        )
        .err(),
        Some("the opening offered is not the value that was proved")
    );
}

// --- writing the tranches down --------------------------------------------

#[test]
fn a_resolution_is_written_down_once() {
    let mut rng = OsRng;
    let k = key();
    let amounts = [100u64, 200, 400, 5_000];
    let blindings: Vec<Scalar> = amounts.iter().map(|_| Scalar::random(&mut rng)).collect();
    let tranches: Vec<Tranche> = amounts
        .iter()
        .zip(&blindings)
        .enumerate()
        .map(|(i, (a, b))| Tranche {
            name: format!("t{i}"),
            commitment: k.commit_u64(*a, b),
        })
        .collect();
    let waterfall = Waterfall::new(k.clone(), tranches.clone(), 64);
    let (resolution, drawn) = waterfall
        .build(
            500,
            &Scalar::random(&mut rng),
            &amounts,
            &blindings,
            &mut rng,
        )
        .unwrap();
    assert_eq!(drawn, vec![100, 200, 200, 0]);

    let tranches_before = tranches.clone();
    let mut book = TrancheBook::new(tranches);
    assert_eq!(book.apply(k.clone(), 64, &resolution, &mut rng), Ok(()));
    assert_eq!(book.applied_count(), 1);
    // Every tranche's commitment moves, including the ones drawn zero: a draw
    // of nothing still carries a blinding, so `C - draw` re-blinds a tranche
    // that lost no value. Which is right --- a tranche whose commitment did not
    // move would say publicly that it was untouched.
    for (after, before) in book.tranches.iter().zip(&tranches_before) {
        assert_ne!(after.commitment, before.commitment);
    }
    // and a second application of the same one is refused
    assert_eq!(
        book.apply(k, 64, &resolution, &mut rng).err(),
        Some("this resolution has already been written down")
    );
}

#[test]
fn a_resolution_proved_against_a_fuller_book_does_not_verify_against_a_drawn_one() {
    // What stops a second default being absorbed by capital the first one ate.
    let mut rng = OsRng;
    let k = key();
    let amounts = [100u64, 200, 400, 5_000];
    let blindings: Vec<Scalar> = amounts.iter().map(|_| Scalar::random(&mut rng)).collect();
    let tranches: Vec<Tranche> = amounts
        .iter()
        .zip(&blindings)
        .enumerate()
        .map(|(i, (a, b))| Tranche {
            name: format!("t{i}"),
            commitment: k.commit_u64(*a, b),
        })
        .collect();
    let waterfall = Waterfall::new(k.clone(), tranches.clone(), 64);
    let (first, _) = waterfall
        .build(
            500,
            &Scalar::random(&mut rng),
            &amounts,
            &blindings,
            &mut rng,
        )
        .unwrap();
    let (second, _) = waterfall
        .build(
            120,
            &Scalar::random(&mut rng),
            &amounts,
            &blindings,
            &mut rng,
        )
        .unwrap();

    let mut book = TrancheBook::new(tranches);
    assert_eq!(book.apply(k.clone(), 64, &first, &mut rng), Ok(()));
    // the second was proved against the full book and the book is not full now
    assert!(book.apply(k, 64, &second, &mut rng).is_err());
}

#[test]
fn two_resolutions_of_the_same_shortfall_drawing_differently_are_different() {
    let mut rng = OsRng;
    let k = key();
    let amounts = [1_000u64, 200];
    let blindings: Vec<Scalar> = amounts.iter().map(|_| Scalar::random(&mut rng)).collect();
    let tranches: Vec<Tranche> = amounts
        .iter()
        .zip(&blindings)
        .enumerate()
        .map(|(i, (a, b))| Tranche {
            name: format!("t{i}"),
            commitment: k.commit_u64(*a, b),
        })
        .collect();
    let waterfall = Waterfall::new(k, tranches, 64);
    let (a, _) = waterfall
        .build(
            300,
            &Scalar::random(&mut rng),
            &amounts,
            &blindings,
            &mut rng,
        )
        .unwrap();
    let (b, _) = waterfall
        .build(
            300,
            &Scalar::random(&mut rng),
            &amounts,
            &blindings,
            &mut rng,
        )
        .unwrap();
    // different blindings, so different commitments, so different identifiers
    assert_ne!(resolution_id(&a), resolution_id(&b));
}
