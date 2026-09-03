use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    mode: &'static str,
    makers: usize,
    reference: &'static str,
    persist_wires: bool,
    binding_limit: bool,
    input_check: bool,
    audit_gates: bool,
    shamir_inputs: bool,
}

const CASES: [Case; 6] = [
    Case {
        name: "rfq_4_anchored_all_off",
        mode: "rfq",
        makers: 4,
        reference: "anchored",
        persist_wires: false,
        binding_limit: false,
        input_check: false,
        audit_gates: false,
        shamir_inputs: false,
    },
    Case {
        name: "rfq_16_none_all_on_shamir",
        mode: "rfq",
        makers: 16,
        reference: "none",
        persist_wires: true,
        binding_limit: true,
        input_check: true,
        audit_gates: true,
        shamir_inputs: true,
    },
    Case {
        name: "rfm_4_none_input_shamir",
        mode: "rfm",
        makers: 4,
        reference: "none",
        persist_wires: true,
        binding_limit: false,
        input_check: true,
        audit_gates: false,
        shamir_inputs: true,
    },
    Case {
        name: "rfm_16_anchored_binding_audit",
        mode: "rfm",
        makers: 16,
        reference: "anchored",
        persist_wires: false,
        binding_limit: true,
        input_check: false,
        audit_gates: true,
        shamir_inputs: false,
    },
    Case {
        name: "rfs_4_anchored_binding",
        mode: "rfs",
        makers: 4,
        reference: "anchored",
        persist_wires: true,
        binding_limit: true,
        input_check: false,
        audit_gates: false,
        shamir_inputs: false,
    },
    Case {
        name: "rfs_16_none_input_audit_shamir",
        mode: "rfs",
        makers: 16,
        reference: "none",
        persist_wires: false,
        binding_limit: false,
        input_check: true,
        audit_gates: true,
        shamir_inputs: true,
    },
];

// Versioned generator contract. V4 added all four pre-signed Taker fields to
// the input-consistency check. V5 removes stale implementation-language prose
// from the generated source without changing its circuit semantics. V6 emits
// the approved policy DSL as executable pricing code. V7 gates RFQ output and
// persisted winner witnesses with the secret real/cover bit.
// V8 (reissued 2026-09-03): only the profile that persists the DvP witness
// changes, because the generated DvP block now carries the winning Maker's
// pool-before opening and its remainder range proof and takes the Taker's
// buy-side cash reserve from the priced amount; see all_files_parity.rs for
// the provenance of that generator revision.
const GENERATOR_V8_PROGRAM_CONTRACT: [(&str, usize, &str); 6] = [
    (
        "rfq_4_anchored_all_off",
        9_596,
        "f21a46fd9db11d62d5b32f92e8ee06485e242b9ea0978f1e5596cd733e824452",
    ),
    (
        "rfq_16_none_all_on_shamir",
        19_019,
        "d97bb739f87f12419d64200ffaecc773ee2ee82c4aaa3e0acb57facbdb58d04c",
    ),
    (
        "rfm_4_none_input_shamir",
        11_341,
        "d4a91be0267b59bc41262dc1257e738df85391e4b872e99d80d9c6e985cf7560",
    ),
    (
        "rfm_16_anchored_binding_audit",
        12_512,
        "782b5b83c142e522e2c28411595592a80640c0e82156a9cb34868c0df8fb26f3",
    ),
    (
        "rfs_4_anchored_binding",
        12_350,
        "c865d64982a6397856d369d7a204f636875c8bd73bd2337c6bcc544c74db88ac",
    ),
    (
        "rfs_16_none_input_audit_shamir",
        12_334,
        "719d2ba38570c85305903c84dda4548058031cde242f548ac2e06f92e28c44fc",
    ),
];

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "qomm-program-parity-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("parity test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn options(case: Case) -> Vec<String> {
    let mut args = vec![
        "--mode".into(),
        case.mode.into(),
        "--n-mm".into(),
        case.makers.to_string(),
        "--bit-length".into(),
        "31".into(),
        "--reference".into(),
        case.reference.into(),
    ];
    for (enabled, option) in [
        (case.persist_wires && case.mode == "rfq", "--persist-wires"),
        (case.binding_limit, "--binding-limit"),
        (case.input_check, "--input-check"),
        (case.audit_gates, "--audit-gates"),
    ] {
        if enabled {
            args.push(option.into());
        }
    }
    if case.shamir_inputs {
        args.extend([
            "--shamir-inputs".into(),
            "--field-bits".into(),
            "253".into(),
        ]);
    }
    args
}

fn assert_success(label: &str, output: std::process::Output) {
    assert!(
        output.status.success(),
        "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn output_options(program: &Path, inputs: &Path, reference: &Path) -> [String; 6] {
    [
        "--out-program".into(),
        program.display().to_string(),
        "--out-input-dir".into(),
        inputs.display().to_string(),
        "--out-reference".into(),
        reference.display().to_string(),
    ]
}

#[test]
fn rust_cli_matches_the_versioned_generator_program_contract() {
    let directory = TestDir::new();
    let rust_generator = env!("CARGO_BIN_EXE_qomm-gen");

    let mut mismatches = Vec::new();
    for (case, (contract_name, expected_bytes, expected_sha256)) in
        CASES.into_iter().zip(GENERATOR_V8_PROGRAM_CONTRACT)
    {
        assert_eq!(case.name, contract_name);
        let rust_program = directory.0.join(format!("{}.mpc", case.name));

        // Persistence is an RFQ-only contract. Keep this byte-parity matrix on
        // valid configurations; Rust's non-RFQ refusal is asserted separately
        // in all_files_parity.rs.
        let mut rust_args = options(case);
        rust_args.extend(output_options(
            &rust_program,
            &directory.0.join("rust-input"),
            &directory.0.join("rust-reference.json"),
        ));
        let rust = Command::new(rust_generator)
            .args(&rust_args)
            .output()
            .expect("run Rust generator");
        assert_success(&format!("Rust case {}", case.name), rust);

        let bytes = fs::read(&rust_program).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));
        if bytes.len() != expected_bytes || digest != expected_sha256 {
            mismatches.push(format!(
                "{}: expected ({expected_bytes}, {expected_sha256}), actual ({}, {digest})",
                case.name,
                bytes.len()
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "versioned program contract changed:\n{}",
        mismatches.join("\n")
    );
}
