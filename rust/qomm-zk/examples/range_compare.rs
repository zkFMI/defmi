//! Bit decomposition at its own width against Bulletproofs at the width it
//! rounds up to, in one language on one machine.
//!
//! `DEPLOYMENT.md` reports 6.3x on verification and 10.5x on package size, but
//! that pair is Python bit decomposition against Rust Bulletproofs, so the
//! language is confounded with the scheme. Both are in Rust now.
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::bitrange;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use rand::rngs::OsRng;
use std::time::Instant;

fn ms(t: Instant, n: u32) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0 / f64::from(n)
}

fn main() {
    let key = Pedersen::new(b"qomm:compare");
    let mut rng = OsRng;
    const REPS: u32 = 20;
    println!(
        "{:>6} {:>10} {:>11} {:>11} {:>9} | {:>6} {:>11} {:>11} {:>9}",
        "bits", "scheme", "prove ms", "verify ms", "bytes", "bp@", "prove ms", "verify ms", "bytes"
    );
    for bits in [8usize, 16, 24, 32, 40, 48, 64] {
        let value: u64 = if bits >= 64 {
            u64::MAX / 3
        } else {
            (1u64 << bits) - 7
        };
        let blinding = Scalar::random(&mut rng);
        let commitment = key.commit(&Scalar::from(value), &blinding);

        let t = Instant::now();
        let mut bd = None;
        for _ in 0..REPS {
            bd = Some(
                bitrange::prove_range(&key, &commitment, value, &blinding, bits, b"cmp", &mut rng)
                    .expect("in range"),
            );
        }
        let bd_prove = ms(t, REPS);
        let bd = bd.unwrap();
        let t = Instant::now();
        for _ in 0..REPS {
            assert!(bitrange::verify_range(&key, &commitment, &bd, b"cmp"));
        }
        let bd_verify = ms(t, REPS);
        let bd_bytes = bd.bit_commitments.len() * 32 + bd.bit_proofs.len() * 32 * 5;

        // what bulletproofs would have to use for the same value
        let rounded = bits.next_power_of_two().max(8);
        let ctx = RangeCtx::new(rounded, 1);
        let t = Instant::now();
        let mut bp = None;
        for _ in 0..REPS {
            let mut tr = Transcript::new(b"cmp");
            bp = Some(ctx.prove(&mut tr, &[value], &[blinding]).expect("in range"));
        }
        let bp_prove = ms(t, REPS);
        let (proof, coms) = bp.unwrap();
        let t = Instant::now();
        for _ in 0..REPS {
            let mut tr = Transcript::new(b"cmp");
            assert!(ctx.verify(&mut tr, &proof, &coms));
        }
        let bp_verify = ms(t, REPS);
        let bp_bytes = proof.to_bytes().len();

        println!(
            "{bits:>6} {:>10} {bd_prove:>11.3} {bd_verify:>11.3} {bd_bytes:>9} | {rounded:>6} {bp_prove:>11.3} {bp_verify:>11.3} {bp_bytes:>9}",
            "bitdecomp"
        );
    }
}
