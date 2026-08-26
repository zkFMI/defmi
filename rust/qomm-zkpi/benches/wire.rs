//! What accepting an instruction costs, and what that means for where it runs.
//!
//! `run_evm.py` measured one ed25519 scalar multiplication in the EVM at
//! 302,401 gas, which puts a whole verification far past a block. The reason
//! that number matters is not that the arithmetic is expensive --- it is
//! microseconds here --- but that the EVM has no curve to do it on, so every
//! operation is simulated in 256-bit words.
//!
//! Which makes the deployment question a specific one rather than a general
//! one: **not "which chain is cheap" but "which chain lets us add the curve".**
//! Ethereum L1 does not; its precompiles are fixed by consensus. An Avalanche
//! L1 does --- Subnet-EVM takes stateful precompiles as a build-time
//! configuration --- and so does anything with a custom execution layer. The
//! measurement below is what such a precompile would actually do, so pricing it
//! is arithmetic rather than guesswork.

use qomm_measure::{hosts, time_us};
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::wire::{decode, encode};
use qomm_zkpi::{wire_vectors, Bounds, Venue};

/// The going rate at which EVM chains price a precompile: roughly the gas a
/// comparable native operation is charged. `ecrecover` is 3,000 gas for about
/// 45 microseconds of secp256k1, which is the closest reference point there is.
const ECRECOVER_GAS: f64 = 3_000.0;
const ECRECOVER_US: f64 = 45.0;

/// What `run_evm.py` measured for one ed25519 scalar multiplication written in
/// EVM bytecode.
const IN_EVM_SCALAR_MUL_GAS: f64 = 302_401.0;

fn shell(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn main() {
    let (instruction, package) = wire_vectors::sample_with_quorum();
    let bytes = encode(&instruction);
    let mut venue = Venue::new(Pedersen::new(b"qomm:defmi:v1"), &Bounds::default(), package);
    venue.domain = qomm_zkpi::DEFAULT_DOMAIN.to_vec();
    let now = instruction.deadline - 1;

    let encoding = time_us(200, || {
        encode(&instruction);
    });
    let decoding = time_us(200, || {
        decode(&bytes).unwrap();
    });
    let verifying = time_us(50, || {
        venue.verify(&instruction, now).unwrap();
    });
    let whole = time_us(50, || {
        let back = decode(&bytes).unwrap();
        venue.verify(&back, now).unwrap();
    });

    println!("A zero-knowledge payment instruction on the wire\n");
    println!("  size            {} bytes", bytes.len());
    println!("  encode          {:.1} us", encoding.median);
    println!("  decode          {:.1} us", decoding.median);
    println!("  verify          {:.1} us", verifying.median);
    println!(
        "  off the wire    {:.1} us  (decode and verify)",
        whole.median
    );

    let as_precompile = whole.median / ECRECOVER_US * ECRECOVER_GAS;
    println!(
        "\nPriced the way an EVM chain prices a precompile --- ecrecover is \
              {ECRECOVER_GAS:.0} gas\nfor about {ECRECOVER_US:.0} us of secp256k1:\n"
    );
    println!(
        "  a whole verification as a precompile  {:>10.0} gas",
        as_precompile
    );
    println!(
        "  one scalar mult in EVM bytecode       {:>10.0} gas  (measured)",
        IN_EVM_SCALAR_MUL_GAS
    );
    println!(
        "  ratio                                 {:>10.1}x",
        IN_EVM_SCALAR_MUL_GAS / as_precompile
    );
    println!(
        "\nAnd one scalar multiplication is a fraction of a verification, so the\n\
              real ratio is larger than that. What to take from it is not the gas ---\n\
              it is that the deployment requirement is a chain that lets a curve be\n\
              added, which Ethereum L1 does not and an Avalanche L1 does."
    );

    if let Ok(path) = std::env::var("QOMM_BENCH_JSON") {
        let json = format!(
            "{{\n  \"host\": \"{}\",\n  \"rustc\": \"{}\",\n  \
\"wire_bytes\": {},\n  \"encode_us\": {},\n  \"decode_us\": {},\n  \
\"verify_us\": {},\n  \"off_the_wire_us\": {},\n  \
\"as_precompile_gas\": {:.0},\n  \"in_evm_scalar_mul_gas\": {},\n  \
\"ratio_against_one_scalar_mult\": {:.1},\n  \
\"pricing\": \"ecrecover at {} gas for about {} us of secp256k1, the closest \
reference point an EVM chain has\",\n  \
\"deployment_requirement\": \"a chain that permits adding a curve as a \
precompile. Ethereum L1 does not --- its precompiles are fixed by consensus. \
An Avalanche L1 does, because Subnet-EVM takes stateful precompiles as a \
build-time configuration.\"\n}}\n",
            std::env::var("QOMM_HOST_LABEL").unwrap_or_else(|_| hosts::this_host()),
            shell("rustc", &["--version"]),
            bytes.len(),
            encoding.json(),
            decoding.json(),
            verifying.json(),
            whole.json(),
            as_precompile,
            IN_EVM_SCALAR_MUL_GAS,
            IN_EVM_SCALAR_MUL_GAS / as_precompile,
            ECRECOVER_GAS,
            ECRECOVER_US
        );
        std::fs::write(&path, json).expect("could not write the measurement");
        println!("\nwrote {path}");
    }
}
