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
const GENERATOR_V7_ALL_FILES_CONTRACT: [(&str, usize, usize, &str); 27] = [
    (
        "rfq_baseline",
        9,
        17_826,
        "d4aeffd35f5ab5e91296091dbed1bbe1558d3824f5d9e56a958ebe9d37361e61",
    ),
    (
        "rfm_baseline",
        9,
        17_217,
        "5228941d67f6bad1cc941d57e9b37edd0947a174d7194d8efc9ce427a5884cbd",
    ),
    (
        "rfs_baseline",
        9,
        17_632,
        "709a7d5bb593de8daa1f1218db523c8cf9ecee0c0f47c7fc36dd6ce547a59dc3",
    ),
    (
        "rfq_persist_shamir",
        9,
        103_376,
        "2f59e3fcdbb65aaaf806e053d6035600151952b5a56de05f171abc437ba8ad82",
    ),
    (
        "rfm_persist_shamir",
        9,
        100_419,
        "bb8504415977e89b9391fa6fc1c9acccff2fb611fae7b5e5acc9f29051c97719",
    ),
    (
        "rfs_persist_shamir",
        9,
        100_834,
        "04a0f2753b8ac1f59e4ef0508c7d0cdb91b3f5ed3143382f89e7b7121b65f980",
    ),
    (
        "rfq_binding_check_audit",
        9,
        25_280,
        "1fba1a01e475bfe3aba9c73a00d28e052e75666ff1a08fd4eb63646998537174",
    ),
    (
        "rfm_binding_check_audit",
        9,
        23_641,
        "c55a63f2048f624d42078e74f729cdbc2c8a77d362632133fd27f13418798ef0",
    ),
    (
        "rfs_binding_check_audit",
        9,
        24_056,
        "29afa818a536c5f7f666f7c717c019d17b62117c1aefbf89d42b434ad121e9c1",
    ),
    (
        "rfq_all_on_shamir",
        9,
        112_770,
        "578320e3004e9046b34b4e3dcd483e4994d800e3cff881efa0a592cb6e2406e0",
    ),
    (
        "rfm_all_on_shamir",
        9,
        108_783,
        "2c1490384227c84437fb10dea7c32f08ce130909f0bbf810420b83745cf794f5",
    ),
    (
        "rfs_all_on_shamir",
        9,
        109_198,
        "37612c7bfbd40fbd66a4035f7206a9a28deabf4436d98d8a1f2c7e400de7e178",
    ),
    (
        "rfq_padded_non_power",
        9,
        20_171,
        "3db4df51e7005afb42dd554365b97dd83891462efcd5d42041c9e2d6815ce3ad",
    ),
    (
        "rfm_padded_non_power",
        9,
        19_562,
        "e6ab265b4f1b3933756355dcf548233a2dc36ae2acfd771127ae1e6561bcb781",
    ),
    (
        "rfs_padded_non_power",
        9,
        19_977,
        "d0ac4b3cccdf505d290b66f4ed2dd1db5b5ba85cea02b837b3b9da302ed3e6c0",
    ),
    (
        "rfq_sell_cover_no_ref",
        9,
        101_583,
        "dd39b34eba7aa56a3767fd522b8b28daf22b77a594cf937ae42e0a5dfb604482",
    ),
    (
        "rfm_sell_cover_no_ref",
        9,
        100_974,
        "96d541932966d5f9c2bc664b6bbe4b0ca131f6d955d574edaee66674c6299225",
    ),
    (
        "rfs_sell_cover_no_ref",
        9,
        101_389,
        "3aa862429a1dbaafb7822713a43f9b227e95c9661e4149b2707c155f3bd6035f",
    ),
    (
        "rfq_multi_asset_batch",
        9,
        18_519,
        "47394ee3d084379adf433ceca5f7efe20aac65ffb0b44cb4f5aec2ef0d1eb087",
    ),
    (
        "rfm_multi_asset_batch",
        9,
        17_910,
        "4ec6792ad2136183ded96ddd2374269183d18f83b7879a4f5c3fad070e750177",
    ),
    (
        "rfs_multi_asset_batch",
        9,
        18_325,
        "84af7a4eed780ab588c0304c152a5e02f8f62ca92dd88c1679d6a7e1cf56cc94",
    ),
    (
        "rfq_inputs_only_shamir",
        8,
        29_283,
        "704a390d3183bffb5a7d16eecc1f7ac7336759b45fa1522cc07a8115eeb8d98f",
    ),
    (
        "rfm_inputs_only_shamir",
        8,
        29_283,
        "2298129bb535806dcb1be3d22f81aa684da1f51692736e09f010078229a8f2e4",
    ),
    (
        "rfs_inputs_only_shamir",
        8,
        29_283,
        "fa8381907d572028d4d9b0aa3f606b820ad439e6a0d73ad4f2c5df6ba38d9554",
    ),
    (
        "rfq_supplied_policies_coefficients",
        9,
        41_333,
        "25b760b457830de73214cfd3afc53eaf5f8717b3d99c137622b77be2f2ce424d",
    ),
    (
        "rfm_supplied_policies_coefficients",
        9,
        40_724,
        "3f7c116e5386d7a4334be430b1112984233cc9687c6d7e2e68f7b10eb828c18c",
    ),
    (
        "rfs_supplied_policies_coefficients",
        9,
        41_139,
        "d76074487fb6034da72f45a8c0697c9b0690acfc1db10ff1568f31390b6c904b",
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
    let mut contracts = GENERATOR_V7_ALL_FILES_CONTRACT.into_iter();
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
