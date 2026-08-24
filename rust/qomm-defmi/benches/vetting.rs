//! What it costs to prove a handle was vetted, at each crowd size.
//!
//! The shape to expect is the one every one-out-of-many proof in this stack
//! has: the wire grows by a constant per doubling, because the proof is
//! logarithmic, and the verifier's work doubles, because checking it is a
//! multi-exponentiation over the whole group. That is the trade the crowd size
//! is chosen against --- a bigger crowd is barely more bytes and linearly more
//! verification, so the ceiling is the verifier's, not the wire's.

use curve25519_dalek::scalar::Scalar;
use qomm_defmi::vetting::{check_membership, handle_of, prove_membership, Operator, Roll};
use qomm_measure::{hosts, time_ms};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

const COHORT: &[u8] = b"JP/broker/tier3";
const REPEATS: usize = 200;

fn shell(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn main() {
    let rng = &mut OsRng;
    let key = Pedersen::new(b"qomm:defmi:vetting");
    let operator = Operator::new(key.clone());

    println!("crowd    prove ms    verify ms    proof B   ring B");
    let mut rows = Vec::new();
    for crowd in [4usize, 8, 16, 32, 64, 128] {
        let mut roll = Roll::new(crowd).unwrap();
        // Fill one group, then measure against the *next* one, which holds a
        // single real envelope among decoys. The cost of a one-out-of-many
        // proof is set by the size of the set and not by how much of it is
        // occupied, so this measures the right thing --- but it measures a
        // proof over 128 entries, not a group with 128 firms in it, and saying
        // otherwise would be a claim about occupancy this bench does not make.
        let secrets: Vec<Scalar> = (0..crowd).map(|_| Scalar::random(rng)).collect();
        for secret in &secrets {
            operator.vouch(&mut roll, COHORT, secret, rng);
        }
        let seal = {
            let mut seal = operator.vouch(&mut roll, COHORT, &secrets[0], rng);
            // The first firm of the second group; its own group is full.
            seal.epoch = roll.groups()[seal.group].epoch;
            seal
        };
        let secret = secrets[0];
        let handle = handle_of(&secret);

        let membership = prove_membership(&key, &roll, &seal, &secret, b"bench", rng)
            .expect("an honest holder must be able to prove membership");
        check_membership(&key, &roll, &handle, &membership, b"bench")
            .expect("an honest proof must verify");

        let prove = time_ms(REPEATS, || {
            let _ = prove_membership(&key, &roll, &seal, &secret, b"bench", &mut OsRng).unwrap();
        });
        let verify = time_ms(REPEATS, || {
            check_membership(&key, &roll, &handle, &membership, b"bench").unwrap();
        });
        let bytes = membership.size_bytes();
        let ring = membership.ring.size_bytes();
        println!(
            "{crowd:>5}  {:>10.3}  {:>11.3}  {bytes:>9}  {ring:>7}",
            prove.median, verify.median
        );
        rows.push(format!(
            "    {{\"crowd\": {crowd}, \"prove_ms\": {}, \"verify_ms\": {}, \
\"proof_bytes\": {bytes}, \"ring_bytes\": {ring}}}",
            prove.json(),
            verify.json()
        ));
    }
    println!(
        "\nThe crowd is what a handle hides in. Verification is linear in \n\
              it, so the ceiling on the crowd is the verifier's budget --- and \n\
              the roll publishes the number, so the claim is checkable."
    );

    if let Ok(path) = std::env::var("QOMM_BENCH_JSON") {
        let json = format!(
            "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \"repeats\": {REPEATS},\n  \
\"what\": \"proving a handle was vetted, one-out-of-many over its group\",\n  \
\"rows\": [\n{}\n  ]\n}}\n",
            std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
            shell("rustc", &["--version"]),
            rows.join(",\n")
        );
        std::fs::write(&path, json).expect("could not write the measurement");
        println!("\nwrote {path}");
    }
}
