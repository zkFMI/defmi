use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    makers: usize,
    reference: &'static str,
    persist_wires: bool,
    binding_limit: bool,
    input_check: bool,
    audit_gates: bool,
    shamir_inputs: bool,
    inputs_only: bool,
    use_ref: i128,
    user_dir: i128,
    is_real: i128,
    n_requests: usize,
    n_assets: usize,
    user_asset: usize,
    seed: i128,
    policies: bool,
    coefficients: bool,
}

const PROFILES: [Profile; 9] = [
    Profile {
        name: "baseline",
        makers: 4,
        reference: "anchored",
        persist_wires: false,
        binding_limit: false,
        input_check: false,
        audit_gates: false,
        shamir_inputs: false,
        inputs_only: false,
        use_ref: 1,
        user_dir: 0,
        is_real: 1,
        n_requests: 1,
        n_assets: 1,
        user_asset: 0,
        seed: 7,
        policies: false,
        coefficients: false,
    },
    Profile {
        name: "persist_shamir",
        makers: 16,
        reference: "none",
        persist_wires: true,
        binding_limit: false,
        input_check: false,
        audit_gates: false,
        shamir_inputs: true,
        inputs_only: false,
        use_ref: 1,
        user_dir: 0,
        is_real: 1,
        n_requests: 1,
        n_assets: 1,
        user_asset: 0,
        seed: 7,
        policies: false,
        coefficients: false,
    },
    Profile {
        name: "binding_check_audit",
        makers: 4,
        reference: "none",
        persist_wires: false,
        binding_limit: true,
        input_check: true,
        audit_gates: true,
        shamir_inputs: false,
        inputs_only: false,
        use_ref: 1,
        user_dir: 0,
        is_real: 1,
        n_requests: 1,
        n_assets: 1,
        user_asset: 0,
        seed: 7,
        policies: false,
        coefficients: false,
    },
    Profile {
        name: "all_on_shamir",
        makers: 16,
        reference: "anchored",
        persist_wires: true,
        binding_limit: true,
        input_check: true,
        audit_gates: true,
        shamir_inputs: true,
        inputs_only: false,
        use_ref: 1,
        user_dir: 0,
        is_real: 1,
        n_requests: 1,
        n_assets: 1,
        user_asset: 0,
        seed: 7,
        policies: false,
        coefficients: false,
    },
    Profile {
        name: "padded_non_power",
        makers: 3,
        reference: "anchored",
        persist_wires: false,
        binding_limit: false,
        input_check: true,
        audit_gates: false,
        shamir_inputs: false,
        inputs_only: false,
        use_ref: 1,
        user_dir: 0,
        is_real: 1,
        n_requests: 1,
        n_assets: 1,
        user_asset: 0,
        seed: 7,
        policies: false,
        coefficients: false,
    },
    Profile {
        name: "sell_cover_no_ref",
        makers: 16,
        reference: "none",
        persist_wires: false,
        binding_limit: false,
        input_check: false,
        audit_gates: true,
        shamir_inputs: true,
        inputs_only: false,
        use_ref: 0,
        user_dir: 1,
        is_real: 0,
        n_requests: 1,
        n_assets: 1,
        user_asset: 0,
        seed: 11,
        policies: false,
        coefficients: false,
    },
    Profile {
        name: "multi_asset_batch",
        makers: 4,
        reference: "anchored",
        persist_wires: false,
        binding_limit: false,
        input_check: false,
        audit_gates: false,
        shamir_inputs: false,
        inputs_only: false,
        use_ref: 1,
        user_dir: 1,
        is_real: 1,
        n_requests: 2,
        n_assets: 3,
        user_asset: 2,
        seed: 19,
        policies: false,
        coefficients: false,
    },
    Profile {
        name: "inputs_only_shamir",
        makers: 3,
        reference: "none",
        persist_wires: true,
        binding_limit: true,
        input_check: true,
        audit_gates: false,
        shamir_inputs: true,
        inputs_only: true,
        use_ref: 0,
        user_dir: 1,
        is_real: 0,
        n_requests: 1,
        n_assets: 1,
        user_asset: 0,
        seed: 23,
        policies: false,
        coefficients: false,
    },
    Profile {
        name: "supplied_policies_coefficients",
        makers: 16,
        reference: "anchored",
        persist_wires: false,
        binding_limit: false,
        input_check: true,
        audit_gates: false,
        shamir_inputs: false,
        inputs_only: false,
        use_ref: 0,
        user_dir: 1,
        is_real: 0,
        n_requests: 1,
        n_assets: 3,
        user_asset: 2,
        seed: 29,
        policies: true,
        coefficients: true,
    },
];

// Versioned all-file generator contract. It began as the last exported tree
// generated by the Rust MPC builder; v4 bound all four pre-signed Taker fields
// into the input-consistency check. V5 removes stale implementation-language
// prose from generated source without changing its circuit semantics. V6
// emits the executable price assignments from the checked policy DSL and
// embeds that rule's digest in every generated MPC source. V7 makes the
// real/cover bit gate every RFQ output and persisted winner witness, so a cover
// lane cannot become an unmasked free quote. Each
// digest covers exit status, stdout, stderr, and every sorted output filename
// and byte.
// V8 (reissued 2026-09-03): the DvP witness now carries the winning Maker's
// own pool-before opening (`dvp_maker_pool_before`, `dvp_maker_delivery`,
// `dvp_maker_pool_remainder` with its range-proof bits) so the persisted
// remainder conserves the canonical parent pool note the resident Maker state
// opens, and the Taker's cash reserve for a buy is the priced amount
// (`dvp_cash`) rather than the selected Maker's cash reserve.  The same
// generator revision (rust/qomm-mpc/src/{program.rs,bin/gen.rs,inputs.rs},
// working tree of 2026-09-01, the resident-Maker-state work recorded in
// .codex/project-memory/worklog.jsonl as QOMM-RESIDENT-MAKER-STATE-2026-09-02)
// added the DvP and quote-proof input fields and blindings to every emitted
// input and reference file, which is why every V7 tree grew by a few bytes.
// V7 is retained above as history; the V8 triples were taken from the
// generator's own output on the remote gate host (softbank) and checked
// against an independent run on the OmenX gate host.
const GENERATOR_V8_ALL_FILES_CONTRACT: [(&str, usize, usize, &str); 27] = [
    (
        "rfq_baseline",
        9,
        17_844,
        "d24c2123103dbe57c2884ca28e07f7ee8575fd513afb2151523b6a89ed97f776",
    ),
    (
        "rfm_baseline",
        9,
        17_235,
        "35ce479de5611619ab6de372e7a412449696a2ad898e479800eb9693738187d0",
    ),
    (
        "rfs_baseline",
        9,
        17_650,
        "58c6b29aadbc91dd6bcf3fcbf523604ec141a27e2a881180f33e8783a5802668",
    ),
    (
        "rfq_persist_shamir",
        9,
        103_394,
        "70d83ff0d1e74091f217043c18173d9f3623b25b4f56271b53e9cb9a5468ca9e",
    ),
    (
        "rfm_persist_shamir",
        9,
        100_437,
        "4d9fefe932a477432150c0ecdd90b20dec4616a6e98f95ccc81be254a9c92646",
    ),
    (
        "rfs_persist_shamir",
        9,
        100_852,
        "c3cc9a638850a16a60248d448485f1e03f16cbfd0eb947be247ab06ed24388ca",
    ),
    (
        "rfq_binding_check_audit",
        9,
        25_472,
        "1af0b4ce0ea74e5f117e9470039b865a10ec3a1db097f9d15b4d92dc67c81b3e",
    ),
    (
        "rfm_binding_check_audit",
        9,
        23_668,
        "f52eb38e96ebcfbf1920d6216deb431983816c6782e1636c84a8a34864fb0067",
    ),
    (
        "rfs_binding_check_audit",
        9,
        24_083,
        "5db20f2c648ed73abcc4cb9a60ef98fbb235b70cd6556a78fdb3e4385f5e6a9c",
    ),
    (
        "rfq_all_on_shamir",
        9,
        112_962,
        "d012a701e20d5249fc947eec3231b60a272f5f9424fe6237145b5dd227908806",
    ),
    (
        "rfm_all_on_shamir",
        9,
        108_810,
        "94853140815ffa6b94db6e3ea4dea7b1164c870038ab698a29ef46e42593a8a7",
    ),
    (
        "rfs_all_on_shamir",
        9,
        109_225,
        "8d756744995f100384d56e4851453cb3911eb4d88fa19f711bbdbd639a3a6a54",
    ),
    (
        "rfq_padded_non_power",
        9,
        20_189,
        "7479645d41dedd3b75870e63b5e507fdd81eb9e1da646fbc103fb15b66aa1d89",
    ),
    (
        "rfm_padded_non_power",
        9,
        19_580,
        "0daec12d290b087fb2350d8bd8fbdf8280a5b571a98ef293bb07c819f0684cc9",
    ),
    (
        "rfs_padded_non_power",
        9,
        19_995,
        "9c64b339eed1653a8ee57f8600bb5ffc39ae163f2e12519bc4a53296d0886558",
    ),
    (
        "rfq_sell_cover_no_ref",
        9,
        101_601,
        "3bffd19456aa6b9c94f9749b5ef9d2c4a575988b1a954bcd9b8ebf17a921329d",
    ),
    (
        "rfm_sell_cover_no_ref",
        9,
        100_992,
        "cba7fb1577cb93303c689fbb6d799b89f05cd64da63747de21f49f8ec3f70604",
    ),
    (
        "rfs_sell_cover_no_ref",
        9,
        101_407,
        "2ad412e8253e22c281a9f370fb9186e74731ace99aa7644da3d5bd26b8f9d2ba",
    ),
    (
        "rfq_multi_asset_batch",
        9,
        18_537,
        "786b152a27c95fc7059aa5a62b3362ca2d18351a0acb6434e96aca19f96a1063",
    ),
    (
        "rfm_multi_asset_batch",
        9,
        17_928,
        "b4418802f5d8814bda5651713fb6e78570227a1726888892479b1b632d69ad96",
    ),
    (
        "rfs_multi_asset_batch",
        9,
        18_343,
        "9f19e9f33225a0c134b4422314fd0ef955e15f37d791712da7693f3e28fd84b1",
    ),
    (
        "rfq_inputs_only_shamir",
        8,
        29_309,
        "2a4af894be91e7473fa12d5f0da0bf92aacf0abdd3dd8344afdcaea164e97d49",
    ),
    (
        "rfm_inputs_only_shamir",
        8,
        29_309,
        "d78b6524243a0b4df5a8515c15ead00c64e2e793f947f752b131fe7e81bd3736",
    ),
    (
        "rfs_inputs_only_shamir",
        8,
        29_309,
        "7b30fa8ca9d37d85b5e96d0038d0ef69b761f492a43b274403e8d80911eeaf98",
    ),
    (
        "rfq_supplied_policies_coefficients",
        9,
        41_351,
        "b6523a3828fa2b2a26ca09d62b6bd640c3997fb5ff5416d42a171a175d5be519",
    ),
    (
        "rfm_supplied_policies_coefficients",
        9,
        40_742,
        "ace7f54652be8323efbb58ed1494a8b2381501cf7b2db757da59d2d07c09eb7b",
    ),
    (
        "rfs_supplied_policies_coefficients",
        9,
        41_157,
        "c0fab651555339b7463bb9c16221ddfabdde5958e284672de36995f5a4402cc5",
    ),
];

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("qomm-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn policy_json(count: usize) -> String {
    let entries = (0..count)
        .map(|maker| {
            format!(
                "{{\"asset\":{},\"ask_level\":{},\"spread\":20,\"slope\":1,\"invcoef\":1,\"inv\":{},\"maxqty\":500,\"expiry\":1500,\"active\":1,\"use_ref\":{}}}",
                maker % 3,
                maker as i128 - 8,
                maker as i128 - 4,
                maker % 2
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{entries}]\n")
}

fn common_options(
    profile: Profile,
    mode: &str,
    policies: &Path,
    coefficients: &Path,
) -> Vec<String> {
    let mut options = vec![
        "--mode".into(),
        mode.into(),
        "--n-mm".into(),
        profile.makers.to_string(),
        "--bit-length".into(),
        "31".into(),
        "--reference".into(),
        profile.reference.into(),
        "--use-ref".into(),
        profile.use_ref.to_string(),
        "--user-dir".into(),
        profile.user_dir.to_string(),
        "--is-real".into(),
        profile.is_real.to_string(),
        "--n-requests".into(),
        profile.n_requests.to_string(),
        "--n-assets".into(),
        profile.n_assets.to_string(),
        "--user-asset".into(),
        profile.user_asset.to_string(),
        "--seed".into(),
        profile.seed.to_string(),
    ];
    for (enabled, option) in [
        // silently ignores this flag for RFM/RFS, whereas the Rust generator
        // deliberately refuses that misleading request.  Keep the byte-parity
        // matrix on valid configurations and test the refusal separately.
        (profile.persist_wires && mode == "rfq", "--persist-wires"),
        (profile.binding_limit, "--binding-limit"),
        (profile.input_check, "--input-check"),
        (profile.audit_gates, "--audit-gates"),
        (profile.inputs_only, "--inputs-only"),
    ] {
        if enabled {
            options.push(option.into());
        }
    }
    if profile.shamir_inputs {
        options.extend([
            "--shamir-inputs".into(),
            "--field-bits".into(),
            "253".into(),
        ]);
    }
    if profile.policies {
        options.extend(["--policies".into(), policies.display().to_string()]);
    }
    if profile.coefficients {
        options.extend([
            "--check-coefficients".into(),
            coefficients.display().to_string(),
        ]);
    }
    if matches!(
        profile.name,
        "inputs_only_shamir" | "supplied_policies_coefficients"
    ) {
        options.extend([
            "--check-mode".into(),
            "aggregate".into(),
            "--unsound-check-for-measurement".into(),
            "--check-repeats".into(),
            "3".into(),
        ]);
    }
    options
}

fn output_options(root: &Path) -> [String; 6] {
    [
        "--out-program".into(),
        root.join("prog.mpc").display().to_string(),
        "--out-input-dir".into(),
        root.display().to_string(),
        "--out-reference".into(),
        root.join("ref.json").display().to_string(),
    ]
}

fn assert_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(root)
        .expect("read output directory")
        .map(|entry| {
            let entry = entry.expect("directory entry");
            assert!(entry.file_type().unwrap().is_file());
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).expect("read output file"),
            )
        })
        .collect()
}

fn contract_digest(output: &Output, root: &Path) -> (usize, usize, String) {
    let files = files(root);
    let mut digest = Sha256::new();
    digest.update(format!("status={}\0", output.status.code().unwrap_or(-1)));
    digest.update(b"stdout\0");
    digest.update(&output.stdout);
    digest.update(b"\0stderr\0");
    digest.update(&output.stderr);
    digest.update(b"\0");
    let mut bytes = 0;
    for (name, contents) in &files {
        bytes += contents.len();
        digest.update(name.as_bytes());
        digest.update(b"\0");
        digest.update(contents);
        digest.update(b"\0");
    }
    (files.len(), bytes, hex::encode(digest.finalize()))
}

#[test]
fn all_emitted_files_match_the_versioned_generator_contract_for_27_cases() {
    let directory = TestDir::new("all-files-parity");
    let rust_generator = env!("CARGO_BIN_EXE_qomm-gen");
    let policies = directory.0.join("policies.json");
    let coefficients = directory.0.join("coefficients.json");
    fs::write(&policies, policy_json(16)).unwrap();
    fs::write(&coefficients, "[2, 5, 9]\n").unwrap();

    let mut cases = 0;
    let mut contracts = GENERATOR_V8_ALL_FILES_CONTRACT.into_iter();
    let mut mismatches = Vec::new();
    for profile in PROFILES {
        for mode in ["rfq", "rfm", "rfs"] {
            cases += 1;
            let name = format!("{mode}_{}", profile.name);
            let rust_root = directory.0.join(&name);
            fs::create_dir(&rust_root).unwrap();

            let common = common_options(profile, mode, &policies, &coefficients);
            let rust = Command::new(rust_generator)
                .args(&common)
                .args(output_options(&rust_root))
                .output()
                .expect("run Rust generator");
            assert_success(&format!("Rust case {name}"), &rust);

            let (contract_name, expected_files, expected_bytes, expected_digest) =
                contracts.next().expect("one retired contract per case");
            assert_eq!(name, contract_name);
            let (file_count, bytes, digest) = contract_digest(&rust, &rust_root);
            let expected = 7 + 1 + usize::from(!profile.inputs_only);
            assert_eq!(file_count, expected, "wrong file count for {name}");
            if file_count != expected_files || bytes != expected_bytes || digest != expected_digest
            {
                mismatches.push(format!(
                    "{name}: expected ({expected_files}, {expected_bytes}, {expected_digest}), actual ({file_count}, {bytes}, {digest})"
                ));
            } else {
                println!("CONTRACT\t{name}\t{file_count}\t{bytes}\tIDENTICAL");
            }
        }
    }
    assert_eq!(cases, 27);
    assert!(contracts.next().is_none());
    assert!(
        mismatches.is_empty(),
        "versioned generator contract changed:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn persist_wires_on_non_rfq_is_refused_instead_of_silently_ignored() {
    let rust_generator = env!("CARGO_BIN_EXE_qomm-gen");
    let directory = TestDir::new("non-rfq-persistence-refusal");
    for mode in ["rfm", "rfs"] {
        let root = directory.0.join(mode);
        fs::create_dir(&root).unwrap();
        let output = Command::new(rust_generator)
            .args(["--mode", mode, "--persist-wires"])
            .args(output_options(&root))
            .output()
            .expect("run Rust generator");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert!(stderr.contains("--persist-wires writes wires only on the rfq path"));
        assert!(stderr.contains(&format!("mode is {mode}")));
    }
}

#[test]
fn short_policies_failure_matches_the_versioned_generator_contract() {
    let directory = TestDir::new("policy-failure-parity");
    let rust_generator = env!("CARGO_BIN_EXE_qomm-gen");
    let policies = directory.0.join("policies.json");
    fs::write(&policies, policy_json(8)).unwrap();
    let options = [
        "--inputs-only".to_owned(),
        "--n-mm".into(),
        "16".into(),
        "--policies".into(),
        policies.display().to_string(),
    ];
    let rust_root = directory.0.join("rust");
    fs::create_dir(&rust_root).unwrap();
    let rust = Command::new(rust_generator)
        .args(&options)
        .args(output_options(&rust_root))
        .output()
        .unwrap();

    assert_eq!(rust.status.code(), Some(1));
    assert!(rust.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&rust.stderr),
        "--policies has 8 entries for 16 makers\n"
    );
    assert!(files(&rust_root).is_empty());
}
