//! The sigma protocols, and the batch that settles them together.
//!
//! The batching tests matter more than the single-proof ones. A batch that
//! accepts when one member is invalid is the failure mode worth chasing, and it
//! does not show up unless the test breaks exactly one proof and leaves the
//! rest honest.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::{asset_tag, Pedersen};
use qomm_zk::range::RangeCtx;
use qomm_zk::sigma::*;
use rand::rngs::OsRng;

fn key() -> Pedersen {
    Pedersen::new(b"qomm:defmi:v1")
}

#[test]
fn an_opening_verifies_and_a_wrong_one_does_not() {
    let mut rng = OsRng;
    let k = key();
    let (v, r) = (Scalar::from(1234u64), Scalar::random(&mut rng));
    let c = k.commit(&v, &r);
    let proof = prove_opening(&k, &mut Transcript::new(b"t"), &c, &v, &r, &mut rng);
    assert!(verify_opening(&k, &mut Transcript::new(b"t"), &c, &proof));
    let other = k.commit(&Scalar::from(1235u64), &r);
    assert!(!verify_opening(
        &k,
        &mut Transcript::new(b"t"),
        &other,
        &proof
    ));
    // a different transcript is a different statement
    assert!(!verify_opening(&k, &mut Transcript::new(b"u"), &c, &proof));
}

#[test]
fn a_cross_generator_proof_ties_two_generators() {
    let mut rng = OsRng;
    let k = key();
    let tagged = k.with_value_generator(asset_tag(3));
    let (v, r1, r2) = (
        Scalar::from(100u64),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let (c1, c2) = (tagged.commit(&v, &r1), k.commit(&v, &r2));
    let proof = prove_same_value(
        &k,
        &mut Transcript::new(b"t"),
        &tagged.g,
        &k.g,
        &c1,
        &c2,
        &v,
        &r1,
        &r2,
        &mut rng,
    );
    assert!(verify_same_value(
        &k,
        &mut Transcript::new(b"t"),
        &tagged.g,
        &k.g,
        &c1,
        &c2,
        &proof
    ));
    let wrong = k.commit(&Scalar::from(101u64), &r2);
    assert!(!verify_same_value(
        &k,
        &mut Transcript::new(b"t"),
        &tagged.g,
        &k.g,
        &c1,
        &wrong,
        &proof
    ));
}

#[test]
fn a_product_proof_pins_the_product() {
    let mut rng = OsRng;
    let k = key();
    let (a, b) = (Scalar::from(99_990u64), Scalar::from(100u64));
    let (ra, rb, rc) = (
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let c_a = k.commit(&a, &ra);
    let c_b = k.commit(&b, &rb);
    let c_c = k.commit(&(a * b), &rc);
    let proof = prove_product(
        &k,
        &mut Transcript::new(b"t"),
        &c_a,
        &a,
        &ra,
        &b,
        &rb,
        &rc,
        &mut rng,
    );
    assert!(verify_product(
        &k,
        &mut Transcript::new(b"t"),
        &c_a,
        &c_b,
        &c_c,
        &proof
    ));
    let wrong = k.commit(&(a * b + Scalar::ONE), &rc);
    assert!(!verify_product(
        &k,
        &mut Transcript::new(b"t"),
        &c_a,
        &c_b,
        &wrong,
        &proof
    ));
}

#[test]
fn a_batch_accepts_only_when_every_member_holds() {
    let mut rng = OsRng;
    let k = key();
    let mut good = Vec::new();
    for i in 0..8u64 {
        let (v, r) = (Scalar::from(1000 + i), Scalar::random(&mut rng));
        let c = k.commit(&v, &r);
        let p = prove_opening(&k, &mut Transcript::new(b"t"), &c, &v, &r, &mut rng);
        good.push((c, p));
    }
    let mut batch = Batch::new();
    for (c, p) in &good {
        let w = Batch::weight(&mut rng);
        let (s, pts) = opening_terms(&k, &mut Transcript::new(b"t"), c, p, &w);
        batch.push(s, pts);
    }
    assert!(batch.verify());

    // break exactly one member; the batch must notice
    for broken in 0..good.len() {
        let mut batch = Batch::new();
        for (index, (c, p)) in good.iter().enumerate() {
            let w = Batch::weight(&mut rng);
            let commitment = if index == broken {
                k.commit(&Scalar::from(7u64), &Scalar::random(&mut rng))
            } else {
                *c
            };
            let (s, pts) = opening_terms(&k, &mut Transcript::new(b"t"), &commitment, p, &w);
            batch.push(s, pts);
        }
        assert!(
            !batch.verify(),
            "a batch accepted a broken member at {broken}"
        );
    }
}

#[test]
fn a_batch_of_mixed_proof_kinds_verifies_together() {
    let mut rng = OsRng;
    let k = key();
    let tagged = k.with_value_generator(asset_tag(7));
    let mut batch = Batch::new();

    let (v, r) = (Scalar::from(42u64), Scalar::random(&mut rng));
    let c = k.commit(&v, &r);
    let opening = prove_opening(&k, &mut Transcript::new(b"o"), &c, &v, &r, &mut rng);
    let w = Batch::weight(&mut rng);
    let (s, p) = opening_terms(&k, &mut Transcript::new(b"o"), &c, &opening, &w);
    batch.push(s, p);

    let (r1, r2) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
    let (c1, c2) = (tagged.commit(&v, &r1), k.commit(&v, &r2));
    let cross = prove_same_value(
        &k,
        &mut Transcript::new(b"x"),
        &tagged.g,
        &k.g,
        &c1,
        &c2,
        &v,
        &r1,
        &r2,
        &mut rng,
    );
    let w = Batch::weight(&mut rng);
    let (s, p) = same_value_terms(
        &k,
        &mut Transcript::new(b"x"),
        &tagged.g,
        &k.g,
        &c1,
        &c2,
        &cross,
        &w,
    );
    batch.push(s, p);

    let (a, b) = (Scalar::from(3u64), Scalar::from(5u64));
    let (ra, rb, rc) = (
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let (ca, cb, cc) = (
        k.commit(&a, &ra),
        k.commit(&b, &rb),
        k.commit(&(a * b), &rc),
    );
    let product = prove_product(
        &k,
        &mut Transcript::new(b"p"),
        &ca,
        &a,
        &ra,
        &b,
        &rb,
        &rc,
        &mut rng,
    );
    let w = Batch::weight(&mut rng);
    let (s, p) = product_terms(&k, &mut Transcript::new(b"p"), &ca, &cb, &cc, &product, &w);
    batch.push(s, p);

    assert!(batch.len() >= 20);
    assert!(batch.verify());
}

#[test]
fn an_aggregated_range_proof_covers_every_value() {
    let mut rng = OsRng;
    let ctx = RangeCtx::new(32, 4);
    let values = [10u64, 1_000, 999_999, 0];
    let blindings: Vec<Scalar> = values.iter().map(|_| Scalar::random(&mut rng)).collect();
    let (proof, commitments) = ctx
        .prove(&mut Transcript::new(b"r"), &values, &blindings)
        .expect("prove");
    assert!(ctx.verify(&mut Transcript::new(b"r"), &proof, &commitments));
    // a commitment to something else must not pass
    let mut tampered = commitments.clone();
    tampered[1] = (RistrettoPoint::mul_base(&Scalar::from(5u64))).compress();
    assert!(!ctx.verify(&mut Transcript::new(b"r"), &proof, &tampered));
}

#[test]
fn an_out_of_range_value_is_refused_at_the_call_that_is_wrong() {
    // The crate itself accepts it, proves the truncated value against a
    // commitment to the true one, and leaves the caller to discover the problem
    // when a verifier rejects. Our wrapper refuses instead.
    let mut rng = OsRng;
    let ctx = RangeCtx::new(16, 1);
    let blindings = [Scalar::random(&mut rng)];
    assert!(ctx
        .prove(&mut Transcript::new(b"r"), &[70_000], &blindings)
        .is_err());
    assert!(ctx
        .prove(&mut Transcript::new(b"r"), &[65_535], &blindings)
        .is_ok());
}

/// A forged product proof, to settle whether `verify_product` is sound.
///
/// `product_terms` separates its two verification equations with weights `w`
/// and `w^2` and its own comment says `w` has to be unpredictable once the
/// proof is fixed. `verify_product` passes ONE. With `w = 1` the two equations
/// are added before the check, so what is verified is their sum --- and a sum
/// of two equations does not imply either of them.
///
/// The forgery: pick the two announcements as combinations whose exponents the
/// prover knows, take the challenge, and solve the single aggregate relation
/// for the three responses. `1 + a` is invertible, which is all the prover
/// needs. Nothing here is a factor of anything.
#[test]
fn a_forged_product_proof_is_refused() {
    use curve25519_dalek::traits::Identity;
    use qomm_zk::sigma::{verify_product, ProductProof};

    let mut rng = OsRng;
    let k = Pedersen::new(b"forge");
    let (a, b) = (Scalar::from(2u64), Scalar::from(3u64));
    let lie = Scalar::from(8u64); // the product is 6
    let (ra, rb, rc) = (
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let c_a = k.commit(&a, &ra);
    let c_b = k.commit(&b, &rb);
    let c_c = k.commit(&lie, &rc);

    // announcements the forger knows the exponents of
    let (k1, k2) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
    let t_factor = k.commit(&k1, &k2);
    let t_product = RistrettoPoint::identity();

    // the same challenge the verifier will derive
    let challenge = {
        let mut t = Transcript::new(b"forge");
        t.append_message(b"dom", b"qomm/product");
        t.append_point(b"Ca", &c_a);
        t.append_point(b"Cb", &c_b);
        t.append_point(b"Cc", &c_c);
        t.append_point(b"Tf", &t_factor);
        t.append_point(b"Tp", &t_product);
        t.challenge_scalar(b"c")
    };

    // one equation in three unknowns: solve it
    let z_b = (k1 + challenge * (b + lie)) * (Scalar::ONE + a).invert();
    let z_rb = Scalar::random(&mut rng);
    let z_s = k2 + challenge * (rb + rc) - z_b * ra - z_rb;

    let forged = ProductProof {
        t_factor,
        t_product,
        z_b,
        z_rb,
        z_s,
    };
    let accepted = verify_product(
        &k,
        &mut Transcript::new(b"forge"),
        &c_a,
        &c_b,
        &c_c,
        &forged,
    );
    assert!(
        !accepted,
        "verify_product accepted a proof that 2 x 3 = 8; the two equations \
             are being added before the check instead of separated"
    );
    // and the honest proof still verifies, so the fix did not simply make the
    // verifier refuse everything
    let honest = prove_product(
        &k,
        &mut Transcript::new(b"forge"),
        &c_a,
        &a,
        &ra,
        &b,
        &rb,
        &rc,
        &mut rng,
    );
    let c_true = k.commit(&(a * b), &rc);
    assert!(verify_product(
        &k,
        &mut Transcript::new(b"forge"),
        &c_a,
        &c_b,
        &c_true,
        &honest
    ));
}
