//! A verifier that reads bytes and answers, with nothing else in the process.
//!
//! ```text
//! qomm-zkpi-verify --quorum <hex> --now <unix seconds> [--domain <s>] < instruction.bin
//! qomm-zkpi-verify --vectors <dir>          # write the test vectors
//! qomm-zkpi-verify --check-vectors <dir>    # and check them again
//! ```
//!
//! The point of it being a binary is that "pluggable" is a claim about what
//! somebody else can do without importing this crate. A venue with its own
//! matching engine can shell out to this, or read the layout in `wire.rs` and
//! write its own --- and the vectors are how it finds out whether it did.
//!
//! Exit 0 accepts, 1 rejects, 2 could not be asked.

use std::io::Read;
use std::process::ExitCode;

use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::wire::{decode, fingerprint, hex, WireError};
use qomm_zkpi::{Bounds, Venue};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut quorum = None;
    let mut now = None;
    let mut domain: Option<String> = None;
    let mut vectors: Option<String> = None;
    let mut check: Option<String> = None;
    let mut self_test = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--quorum" => {
                quorum = args.get(i + 1).cloned();
                i += 2;
            }
            "--now" => {
                now = args.get(i + 1).cloned();
                i += 2;
            }
            "--domain" => {
                domain = args.get(i + 1).cloned();
                i += 2;
            }
            "--vectors" => {
                vectors = args.get(i + 1).cloned();
                i += 2;
            }
            "--check-vectors" => {
                check = args.get(i + 1).cloned();
                i += 2;
            }
            "--self-test" => {
                self_test = true;
                i += 1;
            }
            "--spec" => {
                print!("{}", qomm_zkpi::wire::spec());
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }

    if self_test {
        // Issue one, put it on the wire, take it off again, and verify it the
        // way a venue would --- so the binary can demonstrate the whole path
        // without anybody having to hold a quorum key first.
        let (instruction, package) = qomm_zkpi::wire_vectors::sample_with_quorum();
        let bytes = qomm_zkpi::wire::encode(&instruction);
        let back = match decode(&bytes) {
            Ok(i) => i,
            Err(why) => {
                eprintln!("rejected: {why}");
                return ExitCode::from(1);
            }
        };
        let mut venue = Venue::new(Pedersen::new(b"qomm:defmi:v1"), &Bounds::default(), package);
        venue.domain = qomm_zkpi::DEFAULT_DOMAIN.to_vec();
        return match venue.verify(&back, instruction.deadline - 1) {
            Ok(()) => {
                println!(
                    "{} bytes, fingerprint {}",
                    bytes.len(),
                    &hex(&fingerprint(&bytes))[..16]
                );
                println!("accepted --- issued, encoded, decoded and verified");
                ExitCode::SUCCESS
            }
            Err(why) => {
                eprintln!("rejected: {why}");
                ExitCode::from(1)
            }
        };
    }

    if let Some(dir) = vectors.or(check.clone()) {
        return vectors_command(&dir, check.is_some());
    }

    let mut bytes = Vec::new();
    if std::io::stdin().read_to_end(&mut bytes).is_err() {
        eprintln!("could not read the instruction from standard input");
        return ExitCode::from(2);
    }
    println!(
        "{} bytes, fingerprint {}",
        bytes.len(),
        &hex(&fingerprint(&bytes))[..16]
    );

    let instruction = match decode(&bytes) {
        Ok(i) => i,
        Err(why) => {
            eprintln!("rejected: {why}");
            return ExitCode::from(1);
        }
    };
    println!(
        "decoded: deadline {}, quote key {}, {} range commitment(s)",
        instruction.deadline,
        instruction.quote_key,
        instruction.range_commitments.len()
    );

    let (Some(quorum), Some(now)) = (quorum, now) else {
        println!(
            "no --quorum and --now given, so the layout was checked and the \
                  proofs were not. That is a parse, not a verification."
        );
        return ExitCode::SUCCESS;
    };
    let raw = match decode_hex(&quorum) {
        Some(v) => v,
        None => {
            eprintln!("--quorum is a hex-encoded verifying key");
            return ExitCode::from(2);
        }
    };
    // The quorum's public key package, as the venue holds it. A bare verifying
    // key is not enough: the package names the signers, and a venue that took
    // only the group key could not tell one quorum from another that happened
    // to aggregate to the same point.
    let package = match frost_ristretto255::keys::PublicKeyPackage::deserialize(&raw) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("--quorum is a hex-encoded FROST public key package");
            return ExitCode::from(2);
        }
    };
    let now: u64 = match now.parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("--now is seconds since the epoch");
            return ExitCode::from(2);
        }
    };
    let bounds = Bounds::default();
    let mut venue = Venue::new(Pedersen::new(b"qomm:defmi:v1"), &bounds, package);
    if let Some(d) = domain {
        venue.domain = d.into_bytes();
    }
    match venue.verify(&instruction, now) {
        Ok(()) => {
            println!("accepted");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("rejected: {why}");
            ExitCode::from(1)
        }
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// Write the vectors, or read the ones on disk and require them to behave.
///
/// Checking cannot compare against a fresh generation --- a fresh instruction
/// has fresh randomness, so that would fail every time and teach nothing. What
/// it does instead is the check that means something: the accepted vector must
/// decode **and re-encode to the same bytes**, and every other vector must be
/// refused. That is a statement about the file on disk, which is the artefact
/// a second implementation is checking itself against.
fn vectors_command(dir: &str, checking: bool) -> ExitCode {
    if !checking {
        let cases = qomm_zkpi::wire_vectors::build();
        for case in &cases {
            let path = format!("{dir}/{}.bin", case.name);
            if let Err(why) = std::fs::write(&path, &case.bytes) {
                eprintln!("{path}: {why}");
                return ExitCode::from(2);
            }
            println!(
                "wrote   {}  {} bytes  {}  ({})",
                case.name,
                case.bytes.len(),
                &hex(&case.digest)[..16],
                case.why
            );
        }
        return ExitCode::SUCCESS;
    }

    let mut failures = 0;
    for (name, accepts) in [
        ("accepted", true),
        ("wrong-magic", false),
        ("unknown-version", false),
        ("truncated", false),
        ("trailing-byte", false),
        ("not-a-point", false),
    ] {
        let path = format!("{dir}/{name}.bin");
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(why) => {
                eprintln!("MISSING {name}: {why}");
                failures += 1;
                continue;
            }
        };
        let fp = hex(&fingerprint(&bytes))[..16].to_string();
        if accepts {
            match qomm_zkpi::wire_vectors::check(&bytes) {
                Ok(_) => println!("ok      {name}  {} bytes  {fp}", bytes.len()),
                Err(why) => {
                    eprintln!("FAILED  {name}: {why}");
                    failures += 1;
                }
            }
        } else {
            match decode(&bytes) {
                Err(why) => println!("ok      {name}  refused: {why}"),
                Ok(_) => {
                    eprintln!("FAILED  {name}: accepted, and it should not be");
                    failures += 1;
                }
            }
        }
    }
    if failures > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[allow(unused)]
fn unused(_: WireError) {}
