//! An instruction a venue can check without reading, signed by a quorum.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{deal_quorum, frost, Bounds, Issuer, Venue};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

const NODES: u16 = 7;
const THRESHOLD: u16 = 3;

struct Quorum {
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
}

fn quorum(rng: &mut OsRng) -> Quorum {
    let (secret, public) = deal_quorum(NODES, THRESHOLD, rng).expect("deal");
    let shares = secret
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    Quorum { shares, public }
}

/// Two rounds of FROST, as the nodes would run them.
fn sign(q: &Quorum, message: &[u8], signers: usize, rng: &mut OsRng) -> frost::Signature {
    try_sign(q, message, signers, rng).expect("aggregate")
}

fn try_sign(
    q: &Quorum,
    message: &[u8],
    signers: usize,
    rng: &mut OsRng,
) -> Result<frost::Signature, ()> {
    let chosen: Vec<_> = q.shares.keys().take(signers).cloned().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (nonce, commitment) = frost::round1::commit(q.shares[id].signing_share(), rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for id in &chosen {
        // round 2 already refuses a package that names too few signers
        let share = frost::round2::sign(&package, &nonces[id], &q.shares[id]).map_err(|_| ())?;
        shares.insert(*id, share);
    }
    frost::aggregate(&package, &shares, &q.public).map_err(|_| ())
}

fn issue(
    rng: &mut OsRng,
    q: &Quorum,
    amount: u64,
    price: u64,
    deadline: u64,
) -> (qomm_zkpi::Instruction, qomm_zkpi::Openings) {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let issuer = Issuer::new(key, Bounds::default());
    let (digest, openings, partial) = issuer
        .build(
            amount,
            price,
            3,
            RistrettoPoint::mul_base(&Scalar::from(11u64)),
            RistrettoPoint::mul_base(&Scalar::from(22u64)),
            deadline,
            [7u8; 32],
            1_599_845,
            rng,
        )
        .expect("build");
    let signature = sign(q, &digest, THRESHOLD as usize, rng);
    (partial.sealed(signature), openings)
}

fn venue(q: &Quorum) -> Venue {
    Venue::new(
        Pedersen::new(b"qomm:defmi:v1"),
        &Bounds::default(),
        q.public.clone(),
    )
}

#[test]
fn a_signed_instruction_verifies_and_settles_once() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let (instruction, _) = issue(&mut rng, &q, 100, 99_990, 1_500);
    let mut v = venue(&q);
    assert!(v.verify(&instruction, 1_000).is_ok());
    assert!(v.settle(&instruction, 1_000).is_ok());
    assert_eq!(v.settle(&instruction, 1_000), Err("already settled"));
    assert_eq!(v.spent(), 1);
}

#[test]
fn a_second_venue_accepts_the_same_instruction() {
    // pluggability is the property, so it gets a test
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let (instruction, _) = issue(&mut rng, &q, 100, 99_990, 1_500);
    assert!(venue(&q).verify(&instruction, 1_000).is_ok());
    assert!(venue(&q).verify(&instruction, 1_000).is_ok());
}

#[test]
fn an_expired_instruction_is_refused() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let (instruction, _) = issue(&mut rng, &q, 100, 99_990, 1_500);
    assert_eq!(
        venue(&q).verify(&instruction, 2_000),
        Err("past the deadline")
    );
}

#[test]
fn a_tampered_field_breaks_the_signature() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let (mut instruction, _) = issue(&mut rng, &q, 100, 99_990, 1_500);
    let quote_key = instruction.legacy_quote_key().unwrap();
    instruction.quote_binding = qomm_zkpi::QuoteBinding::LegacyPackedKey(quote_key + 1);
    assert_eq!(
        venue(&q).verify(&instruction, 1_000),
        Err("the quorum signature does not verify")
    );
}

#[test]
fn a_signature_does_not_transfer_to_another_instruction() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let (first, _) = issue(&mut rng, &q, 100, 99_990, 1_500);
    let (mut second, _) = issue(&mut rng, &q, 200, 99_990, 1_500);
    second.signature = first.signature;
    assert!(venue(&q).verify(&second, 1_000).is_err());
}

#[test]
fn a_range_proof_from_elsewhere_does_not_cover_this_instruction() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let (mut instruction, _) = issue(&mut rng, &q, 100, 99_990, 1_500);
    let (other, _) = issue(&mut rng, &q, 5, 7, 1_500);
    instruction.ranges = other.ranges;
    assert!(venue(&q).verify(&instruction, 1_000).is_err());
}

#[test]
fn fewer_signers_than_the_threshold_cannot_sign() {
    // FROST refuses to aggregate rather than producing a signature that fails
    // later, which is the stronger of the two behaviours.
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    assert!(try_sign(&q, b"anything", (THRESHOLD - 1) as usize, &mut rng).is_err());
    assert!(try_sign(&q, b"anything", THRESHOLD as usize, &mut rng).is_ok());
}

#[test]
fn an_amount_outside_the_published_bounds_cannot_be_issued() {
    let mut rng = OsRng;
    let issuer = Issuer::new(Pedersen::new(b"qomm:defmi:v1"), Bounds::default());
    assert!(issuer
        .build(
            1u64 << 40,
            99_990,
            3,
            RistrettoPoint::mul_base(&Scalar::from(11u64)),
            RistrettoPoint::mul_base(&Scalar::from(22u64)),
            1_500,
            [7u8; 32],
            1,
            &mut rng
        )
        .is_err());
}

/// A deadline the venue will not hold a nullifier for is refused.
///
/// The bounded-state argument is that a nullifier only has to outlive its
/// deadline, so state grows with instructions in flight rather than with
/// history. That needs an upper bound on how far out a deadline may be, and
/// only "not expired yet" was checked: an instruction dated a century out kept
/// its nullifier for a century, and the argument did not hold.
#[test]
fn a_deadline_beyond_the_venues_horizon_is_refused() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let bounds = Bounds::default();
    let far = 1_000 + bounds.max_horizon + 1;
    let (instruction, _) = issue(&mut rng, &q, 100, 99_990, far);
    assert_eq!(
        venue(&q).verify(&instruction, 1_000),
        Err("the deadline is further out than this venue will hold a \
nullifier for")
    );
}

#[test]
fn a_deadline_inside_the_horizon_is_accepted() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let near = 1_000 + Bounds::default().max_horizon;
    let (instruction, _) = issue(&mut rng, &q, 100, 99_990, near);
    assert!(venue(&q).verify(&instruction, 1_000).is_ok());
}

/// Declaring a narrow amount and a wide price used to buy nothing: one
/// aggregated proof covered both at one width. Now each field is proved at its
/// own, and `each_field_is_proved_at_its_own_width` below is what checks it.
/// This test is what the refusal was, and it is gone.
#[test]
fn a_width_bulletproofs_does_not_take_is_refused_at_construction() {
    // The library takes 8, 16, 32 or 64. Asking for anything else is a
    // programming error and should be one loudly.
    let result = std::panic::catch_unwind(|| qomm_zk::range::RangeCtx::new(24, 1));
    assert!(
        result.is_err(),
        "a width bulletproofs cannot prove was accepted"
    );
}

/// A payment from a handle to itself moves nothing and burns a nullifier.
#[test]
fn a_payment_to_oneself_is_refused() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let handle = RistrettoPoint::mul_base(&Scalar::from(11u64));
    let issuer = Issuer::new(Pedersen::new(b"qomm:zkpi:v1"), Bounds::default());
    let (digest, _, partial) = issuer
        .build(
            100, 99_990, 3, handle, handle, 1_500, [7u8; 32], 1_599_845, &mut rng,
        )
        .unwrap();
    let instruction = partial.sealed(sign(&q, &digest, 3, &mut rng));
    assert_eq!(
        venue(&q).verify(&instruction, 1_000),
        Err("the payer and the payee are the same handle")
    );
}

/// A signature made for one venue must not settle at another. The domain is in
/// the digest, so an instruction built for one does not verify at the other.
#[test]
fn an_instruction_does_not_carry_to_another_venue() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let (instruction, _) = issue(&mut rng, &q, 100, 99_990, 1_500);
    let mut elsewhere = venue(&q);
    elsewhere.domain = b"qomm:some-other-rail".to_vec();
    assert!(
        elsewhere.verify(&instruction, 1_000).is_err(),
        "an instruction signed for one venue settled at another"
    );
}

/// A quorum nobody dealt. `deal_quorum` hands every secret share to one caller,
/// who can then sign alone -- which is the property a quorum exists to remove.
/// It is a fixture, and this is what a deployment runs instead.
#[test]
fn a_dkg_quorum_signs_an_instruction_with_no_dealer() {
    let mut rng = OsRng;
    let (packages, public) = qomm_zkpi::distributed_key_generation(7, 3, &mut rng).expect("dkg");
    assert_eq!(packages.len(), 7);

    let issuer = Issuer::new(Pedersen::new(b"qomm:zkpi:v1"), Bounds::default());
    let (digest, _, partial) = issuer
        .build(
            100,
            99_990,
            3,
            RistrettoPoint::mul_base(&Scalar::from(11u64)),
            RistrettoPoint::mul_base(&Scalar::from(22u64)),
            1_500,
            [7u8; 32],
            1_599_845,
            &mut rng,
        )
        .unwrap();

    let chosen: Vec<_> = packages.keys().take(3).cloned().collect();
    let (mut nonces, mut commitments) = (BTreeMap::new(), BTreeMap::new());
    for id in &chosen {
        let (n, c) = frost::round1::commit(packages[id].signing_share(), &mut rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let package = frost::SigningPackage::new(commitments, &digest);
    let mut shares = BTreeMap::new();
    for id in &chosen {
        shares.insert(
            *id,
            frost::round2::sign(&package, &nonces[id], &packages[id]).unwrap(),
        );
    }
    let signature = frost::aggregate(&package, &shares, &public).unwrap();
    let instruction = partial.sealed(signature);

    let venue = Venue::new(Pedersen::new(b"qomm:zkpi:v1"), &Bounds::default(), public);
    assert_eq!(venue.verify(&instruction, 1_000), Ok(()));
}

/// A narrow amount beside a wide price is worth what it says.
///
/// One aggregated proof covers both fields at one width, so a 24-bit amount
/// declared next to a 64-bit price was proved at 64 and the narrow declaration
/// bought nothing. Two proofs, one per field, buy it back.
#[test]
fn each_field_is_proved_at_its_own_width() {
    let mut rng = OsRng;
    let q = quorum(&mut rng);
    let bounds = Bounds {
        amount_bits: 16,
        price_bits: 32,
        ..Bounds::default()
    };
    let issuer = Issuer::new(Pedersen::new(b"qomm:zkpi:v1"), bounds.clone());

    // inside 16 bits, and inside 32
    let (digest, _, partial) = issuer
        .build(
            1_000,
            99_990,
            3,
            RistrettoPoint::mul_base(&Scalar::from(11u64)),
            RistrettoPoint::mul_base(&Scalar::from(22u64)),
            1_500,
            [7u8; 32],
            1_599_845,
            &mut rng,
        )
        .unwrap();
    let instruction = partial.sealed(sign(&q, &digest, 3, &mut rng));
    let venue = Venue::new(Pedersen::new(b"qomm:zkpi:v1"), &bounds, q.public.clone());
    assert_eq!(venue.verify(&instruction, 1_000), Ok(()));

    // an amount that needs 17 bits: inside the price's width and outside its own
    let wide = issuer.build(
        70_000,
        99_990,
        3,
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        RistrettoPoint::mul_base(&Scalar::from(22u64)),
        1_500,
        [8u8; 32],
        1_599_845,
        &mut rng,
    );
    match wide {
        Err(_) => {} // the prover refuses, which is fine
        Ok((digest, _, partial)) => {
            let instruction = partial.sealed(sign(&q, &digest, 3, &mut rng));
            let venue = Venue::new(Pedersen::new(b"qomm:zkpi:v1"), &bounds, q.public.clone());
            assert_eq!(
                venue.verify(&instruction, 1_000),
                Err("the amount is outside the published bounds"),
                "an amount past its own width passed at the price's width"
            );
        }
    }
}
