//! Netting cycles, and the trade each mode makes.
//!
//! The behavioural distinction is admissibility: a gross rail refuses an order
//! it cannot cover now, a net rail waits until the close. The pair of tests
//! around that is the point of the file.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::credit::CreditCtx;
use qomm_defmi::netting::*;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{deal_quorum, frost, Bounds, Issuer, Venue};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

const BITS: usize = 32;

struct Holder {
    securities: (i64, Scalar),
    cash: (i64, Scalar),
}

struct Fixture {
    key: Pedersen,
    cycle: Cycle,
    issuer: Issuer,
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
    holders: BTreeMap<Vec<u8>, Holder>,
    quorum_key: SigningKey,
}

fn fixture(
    rng: &mut OsRng,
    mode: Mode,
    attest: bool,
    participants: usize,
    securities: &[(usize, i64)],
) -> Fixture {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (sec_tag, _) = registry.blind(3, false, rng).unwrap();
    let (cash_tag, _) = registry.blind(0, false, rng).unwrap();
    let mut sec_book = PositionBook::new(
        key.clone(),
        sec_tag,
        mode.securities_net(),
        "securities",
        BITS,
    );
    let mut cash_book = PositionBook::new(key.clone(), cash_tag, mode.cash_net(), "cash", BITS);
    let mut holders = BTreeMap::new();
    for i in 0..participants {
        let handle = format!("p{i}").into_bytes();
        let opening = securities
            .iter()
            .find(|(j, _)| *j == i)
            .map(|(_, v)| *v)
            .unwrap_or(10_000);
        let holder = Holder {
            securities: (opening, Scalar::random(rng)),
            cash: (10_000_000, Scalar::random(rng)),
        };
        sec_book
            .open(
                &handle,
                sec_book
                    .tagged()
                    .commit(&signed(holder.securities.0), &holder.securities.1),
            )
            .unwrap();
        cash_book
            .open(
                &handle,
                cash_book
                    .tagged()
                    .commit(&signed(holder.cash.0), &holder.cash.1),
            )
            .unwrap();
        holders.insert(handle, holder);
    }
    let (secret, public) = deal_quorum(7, 3, rng).unwrap();
    let shares = secret
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let venue = Venue::new(key.clone(), &Bounds::default(), public.clone());
    // the key an attested cycle's batch attestation verifies under
    let quorum_key = SigningKey::from_bytes(&[7u8; 32]);
    Fixture {
        issuer: Issuer::new(key.clone(), Bounds::default()),
        cycle: Cycle::new(
            key.clone(),
            b"cycle-2026-08-24".to_vec(),
            mode,
            sec_book,
            cash_book,
            venue,
            attest,
            Some(quorum_key.verifying_key()),
        )
        .unwrap(),
        quorum_key,
        key,
        shares,
        public,
        holders,
    }
}

fn signed(value: i64) -> Scalar {
    if value >= 0 {
        Scalar::from(value as u64)
    } else {
        -Scalar::from((-value) as u64)
    }
}

fn sign(f: &Fixture, message: &[u8], rng: &mut OsRng) -> frost::Signature {
    let chosen: Vec<_> = f.shares.keys().take(3).cloned().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (n, c) = frost::round1::commit(f.shares[id].signing_share(), rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let mut sig_shares = BTreeMap::new();
    for id in &chosen {
        sig_shares.insert(
            *id,
            frost::round2::sign(&package, &nonces[id], &f.shares[id]).unwrap(),
        );
    }
    frost::aggregate(&package, &sig_shares, &f.public).unwrap()
}

/// Returns the order and the two delta blindings, which the counterparties have
/// to carry forward: a position is only usable by whoever knows its blinding.
#[allow(clippy::too_many_arguments)]
fn order(
    f: &Fixture,
    seller: &[u8],
    buyer: &[u8],
    quantity: u64,
    price: u64,
    nonce: u8,
    sec_cap: u64,
    sec_cap_blinding: Scalar,
    rng: &mut OsRng,
) -> Result<(Order, Scalar, Scalar), &'static str> {
    let (digest, openings, partial) = f.issuer.build(
        quantity,
        price,
        3,
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        RistrettoPoint::mul_base(&Scalar::from(22u64)),
        1_500,
        [nonce; 32],
        1_599_845,
        rng,
    )?;
    let instruction = partial.sealed(sign(f, &digest, rng));
    let value = quantity * price;
    let cash_blinding = Scalar::random(rng);
    let cash_reference = f.key.commit_u64(value, &cash_blinding);
    let value_proof = prove_cash_reference(
        &f.key,
        &instruction.price_commitment,
        price,
        &openings.price,
        quantity,
        &openings.amount,
        &cash_blinding,
        rng,
    );

    let sold = &f.holders[seller];
    let bought = &f.holders[buyer];
    let sec_delta = Scalar::random(rng);
    let cash_delta = Scalar::random(rng);
    let sec_leg = f.cycle.securities.build_leg(
        seller,
        buyer,
        quantity,
        &sec_delta,
        sold.securities.0,
        &sold.securities.1,
        &instruction.amount_commitment,
        &openings.amount,
        sec_cap,
        &sec_cap_blinding,
        rng,
    )?;
    let cash_leg = f.cycle.cash.build_leg(
        buyer,
        seller,
        value,
        &cash_delta,
        bought.cash.0,
        &bought.cash.1,
        &cash_reference,
        &cash_blinding,
        0,
        &Scalar::ZERO,
        rng,
    )?;
    Ok((
        Order {
            instruction,
            securities: sec_leg,
            cash: cash_leg,
            cash_reference,
            value_proof,
        },
        sec_delta,
        cash_delta,
    ))
}

/// Both sides update their own books, which the cycle never sees.
fn settle_books(
    f: &mut Fixture,
    seller: &[u8],
    buyer: &[u8],
    quantity: u64,
    value: u64,
    sec_delta: Scalar,
    cash_delta: Scalar,
) {
    {
        let s = f.holders.get_mut(seller).unwrap();
        s.securities.0 -= quantity as i64;
        s.securities.1 -= sec_delta;
        s.cash.0 += value as i64;
        s.cash.1 += cash_delta;
    }
    let b = f.holders.get_mut(buyer).unwrap();
    b.securities.0 += quantity as i64;
    b.securities.1 += sec_delta;
    b.cash.0 -= value as i64;
    b.cash.1 -= cash_delta;
}

#[test]
fn every_mode_settles_and_conserves() {
    let mut rng = OsRng;
    for (mode, attest) in [
        (Mode::GrossGross, false),
        (Mode::GrossNet, false),
        (Mode::NetNet, false),
        (Mode::NetNet, true),
    ] {
        let mut f = fixture(&mut rng, mode, attest, 4, &[]);
        for nonce in 0..4u8 {
            let (o, sd, cd) = order(
                &f,
                b"p0",
                b"p1",
                40,
                10_000,
                nonce,
                0,
                Scalar::ZERO,
                &mut rng,
            )
            .expect("build");
            f.cycle.admit(&o, 1_000, &mut rng).expect("admit");
            settle_books(&mut f, b"p0", b"p1", 40, 40 * 10_000, sd, cd);
        }
        assert!(
            f.cycle.securities.conserved() && f.cycle.cash.conserved(),
            "{mode:?} attest={attest}"
        );
    }
}

#[test]
fn a_gross_rail_refuses_a_delivery_it_cannot_cover_yet() {
    // settlement cannot fail, but the order cannot exist
    let mut rng = OsRng;
    let f = fixture(&mut rng, Mode::GrossGross, false, 3, &[(0, 0)]);
    assert_eq!(
        order(&f, b"p0", b"p2", 100, 10_000, 1, 0, Scalar::ZERO, &mut rng).err(),
        Some("the order would leave the position short of its cap")
    );
}

#[test]
fn a_net_rail_lets_the_offsetting_pair_through_in_either_order() {
    // and this is what the trade buys back: order-insensitivity
    let mut rng = OsRng;
    for delivery_first in [true, false] {
        let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[(0, 0)]);
        let mut pairs: Vec<(&[u8], &[u8])> = vec![(b"p0", b"p2"), (b"p1", b"p0")];
        if !delivery_first {
            pairs.reverse();
        }
        for (nonce, (seller, buyer)) in pairs.into_iter().enumerate() {
            let (o, sd, cd) = order(
                &f,
                seller,
                buyer,
                100,
                10_000,
                nonce as u8,
                0,
                Scalar::ZERO,
                &mut rng,
            )
            .expect("build");
            f.cycle.admit(&o, 1_000, &mut rng).expect("admit");
            settle_books(&mut f, seller, buyer, 100, 100 * 10_000, sd, cd);
        }
        let coverage: Vec<_> = f
            .holders
            .iter()
            .map(|(h, holder)| {
                f.cycle
                    .securities
                    .build_coverage(
                        h,
                        holder.securities.0,
                        &holder.securities.1,
                        0,
                        &Scalar::ZERO,
                    )
                    .expect("coverage")
            })
            .collect();
        let cash: Vec<_> = f
            .holders
            .iter()
            .map(|(h, holder)| {
                f.cycle
                    .cash
                    .build_coverage(h, holder.cash.0, &holder.cash.1, 0, &Scalar::ZERO)
                    .expect("cash coverage")
            })
            .collect();
        assert_eq!(f.cycle.close(&coverage, &cash, None), Ok(()));
    }
}

#[test]
fn a_cap_lets_a_net_position_go_below_zero_and_no_further() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[(0, 0)]);
    let cap = 300u64;
    let cap_blinding = Scalar::random(&mut rng);
    // granted under the rail's own key: a cap in other units is incomparable
    let rail_credit = CreditCtx::new(f.cycle.securities.tagged(), 64);
    let line = rail_credit
        .grant(
            b"p0",
            "securities",
            cap,
            &cap_blinding,
            10_000,
            &Scalar::random(&mut rng),
            500,
        )
        .unwrap();
    f.cycle.securities.grant(&rail_credit, line).expect("grant");

    // the buyer pays out of a finite cash position, so the trade has to fit it
    let (o, sd, cd) = order(&f, b"p0", b"p2", 200, 10_000, 1, 0, Scalar::ZERO, &mut rng).unwrap();
    f.cycle.admit(&o, 1_000, &mut rng).expect("admit");
    settle_books(&mut f, b"p0", b"p2", 200, 200 * 10_000, sd, cd);
    assert_eq!(f.holders[&b"p0".to_vec()].securities.0, -200);

    let coverage: Vec<_> = f
        .holders
        .iter()
        .map(|(h, holder)| {
            let (c, cb) = if h == b"p0" {
                (cap, cap_blinding)
            } else {
                (0, Scalar::ZERO)
            };
            f.cycle
                .securities
                .build_coverage(h, holder.securities.0, &holder.securities.1, c, &cb)
                .expect("coverage")
        })
        .collect();
    let cash: Vec<_> = f
        .holders
        .iter()
        .map(|(h, holder)| {
            f.cycle
                .cash
                .build_coverage(h, holder.cash.0, &holder.cash.1, 0, &Scalar::ZERO)
                .unwrap()
        })
        .collect();
    assert_eq!(f.cycle.close(&coverage, &cash, None), Ok(()));
}

#[test]
fn a_position_beyond_its_cap_fails_at_the_close() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[(0, 0)]);
    let cap_blinding = Scalar::random(&mut rng);
    let rail_credit = CreditCtx::new(f.cycle.securities.tagged(), 64);
    let line = rail_credit
        .grant(
            b"p0",
            "securities",
            300,
            &cap_blinding,
            10_000,
            &Scalar::random(&mut rng),
            500,
        )
        .unwrap();
    f.cycle.securities.grant(&rail_credit, line).unwrap();
    let (o, _, _) = order(&f, b"p0", b"p2", 400, 10_000, 1, 0, Scalar::ZERO, &mut rng).unwrap();
    f.cycle.admit(&o, 1_000, &mut rng).unwrap();
    assert!(f
        .cycle
        .securities
        .build_coverage(
            b"p0",
            -400,
            &f.holders[&b"p0".to_vec()].securities.1,
            300,
            &cap_blinding
        )
        .is_err());
}

#[test]
fn a_leg_cannot_pay_itself() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[]);
    let (mut o, _, _) = order(&f, b"p0", b"p1", 40, 100_000, 1, 0, Scalar::ZERO, &mut rng).unwrap();
    o.securities.payee = o.securities.payer.clone();
    assert_eq!(
        f.cycle.admit(&o, 1_000, &mut rng),
        Err("a leg cannot pay itself")
    );
}

#[test]
fn an_instruction_settles_once_per_cycle() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::GrossGross, false, 3, &[]);
    let (o, _, _) = order(&f, b"p0", b"p1", 40, 100_000, 1, 0, Scalar::ZERO, &mut rng).unwrap();
    assert_eq!(f.cycle.admit(&o, 1_000, &mut rng), Ok(()));
    assert_eq!(f.cycle.admit(&o, 1_000, &mut rng), Err("already settled"));
}

#[test]
fn a_batch_attestation_only_makes_sense_when_both_rails_net() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (tag, _) = registry.blind(3, false, &mut rng).unwrap();
    let (secret, public) = deal_quorum(7, 3, &mut rng).unwrap();
    drop(secret);
    for mode in [Mode::GrossGross, Mode::GrossNet] {
        let books = || PositionBook::new(key.clone(), tag.clone(), false, "securities", BITS);
        let venue = Venue::new(key.clone(), &Bounds::default(), public.clone());
        assert!(Cycle::new(
            key.clone(),
            b"cycle-2026-08-24".to_vec(),
            mode,
            books(),
            books(),
            venue,
            true,
            None
        )
        .is_err());
    }
}

#[test]
fn an_attestation_for_other_positions_is_refused() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, true, 3, &[]);
    let (o, sd, cd) = order(&f, b"p0", b"p1", 40, 10_000, 1, 0, Scalar::ZERO, &mut rng).unwrap();
    f.cycle.admit(&o, 1_000, &mut rng).unwrap();
    settle_books(&mut f, b"p0", b"p1", 40, 40 * 10_000, sd, cd);
    let coverage: Vec<_> = f
        .holders
        .iter()
        .map(|(h, holder)| {
            f.cycle.securities.build_coverage(
                h,
                holder.securities.0,
                &holder.securities.1,
                0,
                &Scalar::ZERO,
            )
        })
        .filter_map(|c| c.ok())
        .collect();
    assert_eq!(
        f.cycle.close(
            &coverage,
            &[],
            Some(&BatchAttestation::sign(&f.quorum_key, [0u8; 32]))
        ),
        Err("the attestation is for other positions")
    );
}

/// A batch attestation anyone can compute is not an attestation.
///
/// It used to carry a digest and nothing else, and `close` compared that digest
/// against the cycle's own --- so "attested" meant "the number matches the
/// number", which is an identity rather than a claim. Anyone who had built a
/// cycle could compute its digest and hand it back as the quorum's word.
#[test]
fn a_batch_attestation_signed_by_nobody_is_refused() {
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, true, 3, &[]);
    let (o, sd, cd) = order(&f, b"p0", b"p1", 40, 10_000, 1, 0, Scalar::ZERO, &mut rng).unwrap();
    f.cycle.admit(&o, 1_000, &mut rng).unwrap();
    settle_books(&mut f, b"p0", b"p1", 40, 40 * 10_000, sd, cd);
    let coverage: Vec<_> = f
        .holders
        .iter()
        .map(|(h, holder)| {
            f.cycle.securities.build_coverage(
                h,
                holder.securities.0,
                &holder.securities.1,
                0,
                &Scalar::ZERO,
            )
        })
        .filter_map(|c| c.ok())
        .collect();

    let digest = f.cycle.batch_digest();
    let stranger = SigningKey::from_bytes(&[9u8; 32]);
    assert_eq!(
        f.cycle.close(
            &coverage,
            &[],
            Some(&BatchAttestation::sign(&stranger, digest))
        ),
        Err("the attestation is not signed by the quorum"),
        "a cycle closed on an attestation the quorum never made"
    );
}

#[test]
fn a_book_cannot_be_rebased_after_trades_have_been_admitted() {
    // The opening is what conservation is measured against, so reopening a
    // handle at whatever the trades produced would make the check pass on any
    // state at all.
    let mut rng = OsRng;
    let mut f = fixture(&mut rng, Mode::NetNet, false, 3, &[]);
    let handle = f.holders.keys().next().unwrap().clone();
    let commitment = f
        .cycle
        .securities
        .tagged()
        .commit(&Scalar::from(999u64), &Scalar::ZERO);
    assert_eq!(
        f.cycle.securities.open(&handle, commitment),
        Err("that handle is already open in this book")
    );
}

// --- the width of the arithmetic, which is not the width of the inputs -----

/// A position is `i64` and an amount is `u64`; their difference is neither.
///
/// The headroom used to be computed in `i64` with the amount cast into it. Past
/// `2^63` that cast is negative, so subtracting the amount *added* to the
/// headroom: an order larger than anything the position could cover proved that
/// it was covered. The cast, not the subtraction, is the defect --- the numbers
/// below are chosen so the old expression stayed inside `i64` and no overflow
/// check would have caught it.
#[test]
fn an_order_past_the_signed_range_cannot_prove_itself_covered() {
    let mut rng = OsRng;
    let f = fixture(&mut rng, Mode::GrossGross, false, 2, &[]);
    let book = &f.cycle.securities;
    let huge = (1u64 << 63) + 100; // as i64: -9_223_372_036_854_775_708
    let err = book
        .build_leg(
            b"p0",
            b"p1",
            huge,
            &Scalar::random(&mut rng),
            0,
            &Scalar::random(&mut rng),
            &book.tagged().commit(&Scalar::from(huge), &Scalar::ZERO),
            &Scalar::ZERO,
            0,
            &Scalar::ZERO,
            &mut rng,
        )
        .err()
        .expect("it proved itself covered");
    assert!(
        err.contains("short of its cap"),
        "an order of 2^63+100 against a zero position and no cap: {err}"
    );
}

/// The same cast in the other direction refuses an order that is covered.
///
/// A cap past `2^63` read as negative, so a position with room to spare was
/// told it was short. Harmless to the ledger and fatal to the participant, and
/// it is the same line.
#[test]
fn a_cap_past_the_signed_range_still_covers_what_it_covers() {
    let mut rng = OsRng;
    let f = fixture(&mut rng, Mode::GrossGross, false, 2, &[]);
    let book = &f.cycle.securities;
    let cap = (1u64 << 63) + 100;
    // 64-bit headroom needs a 64-bit proof; the fixture's books are 32.
    let wide = PositionBook::new(f.key.clone(), book.tag.clone(), false, "securities", 64);
    let leg = wide.build_leg(
        b"p0",
        b"p1",
        0,
        &Scalar::random(&mut rng),
        -10,
        &Scalar::random(&mut rng),
        &wide.tagged().commit(&Scalar::ZERO, &Scalar::ZERO),
        &Scalar::ZERO,
        cap,
        &Scalar::random(&mut rng),
        &mut rng,
    );
    assert!(
        leg.is_ok(),
        "a cap of 2^63+100 over a position of -10: {:?}",
        leg.err()
    );
}

/// Headroom that does not fit the proof's width is refused, not truncated.
#[test]
fn headroom_wider_than_the_proof_is_refused_rather_than_wrapped() {
    let mut rng = OsRng;
    let f = fixture(&mut rng, Mode::GrossGross, false, 2, &[]);
    let book = &f.cycle.securities; // 32-bit proofs
    let err = book
        .build_leg(
            b"p0",
            b"p1",
            0,
            &Scalar::random(&mut rng),
            0,
            &Scalar::random(&mut rng),
            &book.tagged().commit(&Scalar::ZERO, &Scalar::ZERO),
            &Scalar::ZERO,
            1 << 40,
            &Scalar::random(&mut rng),
            &mut rng,
        )
        .err()
        .expect("a 2^40 headroom fit a 32-bit proof");
    assert!(err.contains("beyond the range"), "{err}");
}

// --- which cycle the attestation is for ------------------------------------

/// An attestation names a state, and a state is not a cycle.
///
/// `batch_digest` covered the mode, both books' closing positions, and the
/// admitted count. Nothing in it says *which* cycle. Two cycles that end in the
/// same place --- the obvious one being a quiet day, where the book is carried
/// forward and nothing is admitted --- have the same digest, so the quorum's
/// signature over one settles the other. A signature that settles a cycle
/// nobody showed the quorum is the thing the attested mode exists to prevent.
#[test]
fn an_attestation_does_not_move_between_cycles_that_end_the_same_way() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (sec_tag, _) = registry.blind(3, false, &mut rng).unwrap();
    let (cash_tag, _) = registry.blind(0, false, &mut rng).unwrap();
    let (_, public) = deal_quorum(7, 3, &mut rng).unwrap();

    // Same handles, same commitments, same mode: two cycles in the same state.
    let opening: Vec<(Vec<u8>, Scalar)> = (0..3)
        .map(|i| (format!("p{i}").into_bytes(), Scalar::random(&mut rng)))
        .collect();
    let build = |id: &[u8], rng: &mut OsRng| {
        let mut sec = PositionBook::new(key.clone(), sec_tag.clone(), true, "securities", BITS);
        let mut cash = PositionBook::new(key.clone(), cash_tag.clone(), true, "cash", BITS);
        for (handle, blinding) in &opening {
            sec.open(
                handle,
                sec.tagged().commit(&Scalar::from(1_000u64), blinding),
            )
            .unwrap();
            cash.open(
                handle,
                cash.tagged().commit(&Scalar::from(5_000u64), blinding),
            )
            .unwrap();
        }
        let venue = Venue::new(key.clone(), &Bounds::default(), public.clone());
        Cycle::new(
            key.clone(),
            id.to_vec(),
            Mode::NetNet,
            sec,
            cash,
            venue,
            true,
            Some(SigningKey::generate(rng).verifying_key()),
        )
        .unwrap()
    };

    let monday = build(b"2026-08-24", &mut rng);
    let tuesday = build(b"2026-08-25", &mut rng);
    assert_ne!(
        monday.batch_digest(),
        tuesday.batch_digest(),
        "two cycles in the same state produced the same digest, so the \
                quorum's word about one is its word about the other"
    );
}
