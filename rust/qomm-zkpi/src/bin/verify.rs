//! A verifier that reads bytes and answers, with nothing else in the process.
//!
//! ```text
//! qomm-zkpi-verify --quorum <hex> --now <unix seconds> [--domain <s>] < instruction.bin
//! qomm-zkpi-verify --vectors <dir>          # write the test vectors
//! qomm-zkpi-verify --check-vectors <dir>    # and check them again
//! qomm-zkpi-verify --write-spec <path>      # refresh only the generated section
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
use qomm_zkpi::wire::{decode, fingerprint, hex};
use qomm_zkpi::{Bounds, Venue};

const SPEC_BEGIN: &str = "<!-- BEGIN GENERATED WIRE SPEC -->";
const SPEC_END: &str = "<!-- END GENERATED WIRE SPEC -->";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut quorum = None;
    let mut now = None;
    let mut domain: Option<String> = None;
    let mut vectors: Option<String> = None;
    let mut check: Option<String> = None;
    let mut write_spec: Option<String> = None;
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
            "--write-spec" => {
                write_spec = args.get(i + 1).cloned();
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

    if let Some(path) = write_spec {
        return match update_spec_file(&path) {
            Ok(()) => {
                println!("updated generated wire specification in {path}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("could not update {path}: {error}");
                ExitCode::from(2)
            }
        };
    }

    if self_test {
        // Issue one, put it on the wire, take it off again, and verify it the
        // way a venue would --- so the binary can demonstrate the whole path
        // without anybody having to hold a quorum key first.
        let (instruction, package, bounds) =
            qomm_zkpi::wire_vectors::production_sample_with_quorum();
        let bytes = qomm_zkpi::wire::encode(&instruction);
        let back = match decode(&bytes) {
            Ok(i) => i,
            Err(why) => {
                eprintln!("rejected: {why}");
                return ExitCode::from(1);
            }
        };
        let mut venue = Venue::new(Pedersen::new(b"qomm:defmi:v1"), &bounds, package)
            .require_threshold_ranges();
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
        "decoded: deadline {}, quote binding {}, {} range commitment(s)",
        instruction.deadline,
        instruction
            .legacy_quote_key()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "proof-digest".to_string()),
        instruction.range_commitment_count()
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

fn splice_generated_spec(document: &str) -> Result<String, String> {
    let begin = document
        .find(SPEC_BEGIN)
        .ok_or_else(|| format!("missing {SPEC_BEGIN}"))?;
    let after_begin = begin + SPEC_BEGIN.len();
    let relative_end = document[after_begin..]
        .find(SPEC_END)
        .ok_or_else(|| format!("missing {SPEC_END}"))?;
    let end = after_begin + relative_end;
    if document[end + SPEC_END.len()..].contains(SPEC_END) {
        return Err(format!("more than one {SPEC_END}"));
    }
    if document[..begin].contains(SPEC_BEGIN) || document[after_begin..end].contains(SPEC_BEGIN) {
        return Err(format!("more than one {SPEC_BEGIN}"));
    }
    let mut updated = String::with_capacity(document.len() + qomm_zkpi::wire::spec().len());
    updated.push_str(&document[..begin]);
    updated.push_str(SPEC_BEGIN);
    updated.push('\n');
    updated.push_str(qomm_zkpi::wire::spec().trim_end());
    updated.push('\n');
    updated.push_str(SPEC_END);
    updated.push_str(&document[end + SPEC_END.len()..]);
    Ok(updated)
}

fn update_spec_file(path: &str) -> Result<(), String> {
    let document = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let updated = splice_generated_spec(&document)?;
    std::fs::write(path, updated).map_err(|error| error.to_string())
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
        ("accepted-v2", true),
        ("wrong-magic-v2", false),
        ("unknown-version-v2", false),
        ("truncated-v2", false),
        ("trailing-byte-v2", false),
        ("not-a-point-v2", false),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_spec_update_preserves_the_reviewed_tail() {
        let document =
            format!("prefix\n{SPEC_BEGIN}\nstale\n{SPEC_END}\n## Reviewed tail\nkeep me\n");
        let updated = splice_generated_spec(&document).expect("marked document");
        assert!(updated.starts_with("prefix\n"));
        assert!(updated.contains(&qomm_zkpi::wire::spec()));
        assert!(updated.ends_with("## Reviewed tail\nkeep me\n"));
        assert!(!updated.contains("stale"));
    }

    #[test]
    fn generated_spec_update_fails_closed_without_both_markers() {
        assert!(splice_generated_spec("reviewed text only").is_err());
        assert!(splice_generated_spec(&format!("{SPEC_BEGIN}\nno end")).is_err());
    }
}
