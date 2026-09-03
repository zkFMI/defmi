use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

struct TestDir(PathBuf);

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "qomm-{label}-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Emitted {
    program: Vec<u8>,
    counts: BTreeMap<String, usize>,
    reference: Value,
}

fn emit(overrides: &[(&str, &str)]) -> Emitted {
    let directory = TestDir::new("oblivious");
    let input_dir = directory.0.join("inputs");
    let program = directory.0.join("q.mpc");
    let reference = directory.0.join("ref.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_qomm-gen"));
    command.args([
        "--n-mm",
        "8",
        "--n-parties",
        "7",
        "--n-assets",
        "4",
        "--user-asset",
        "0",
        "--user-qty",
        "100",
        "--user-dir",
        "0",
        "--is-real",
        "1",
        "--out-program",
        program.to_str().unwrap(),
        "--out-input-dir",
        input_dir.to_str().unwrap(),
        "--out-reference",
        reference.to_str().unwrap(),
    ]);
    for (name, value) in overrides {
        command.args([*name, *value]);
    }
    let output = command.output().expect("run qomm-gen");
    assert!(
        output.status.success(),
        "qomm-gen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let counts = (0..7)
        .map(|party| {
            let name = format!("Input-P{party}-0");
            let count = fs::read_to_string(input_dir.join(&name))
                .unwrap()
                .split_whitespace()
                .count();
            (name, count)
        })
        .collect();
    Emitted {
        program: fs::read(program).unwrap(),
        counts,
        reference: serde_json::from_str(&fs::read_to_string(reference).unwrap()).unwrap(),
    }
}

const CHANGES: [(&str, &str, &str); 6] = [
    ("the market asked about", "--user-asset", "3"),
    ("the size", "--user-qty", "997"),
    ("the direction", "--user-dir", "1"),
    ("whether the request is real or cover", "--is-real", "0"),
    ("a size no maker can fill", "--user-qty", "10000000"),
    ("the makers' policies", "--seed", "99"),
];

#[test]
fn the_program_does_not_depend_on_the_request() {
    let baseline = emit(&[]).program;
    for (what, name, value) in CHANGES {
        assert_eq!(
            emit(&[(name, value)]).program,
            baseline,
            "changing {what} changed the program the nodes run"
        );
    }
}

#[test]
fn every_node_reads_the_same_number_of_values_whatever_is_asked() {
    let baseline = emit(&[]).counts;
    for (what, name, value) in CHANGES {
        assert_eq!(
            emit(&[(name, value)]).counts,
            baseline,
            "changing {what} changed the input shape"
        );
    }
    assert_eq!(
        baseline
            .values()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        1,
        "the parties do not all read the same number of values"
    );
}

#[test]
fn a_request_nobody_can_fill_runs_the_same_program() {
    let baseline = emit(&[]);
    let unfillable = emit(&[("--user-qty", "10000000")]);
    assert_eq!(unfillable.program, baseline.program);
    assert_eq!(unfillable.counts, baseline.counts);
    assert!(baseline.reference["eligible_count"].as_u64().unwrap() > 0);
    assert!(
        unfillable.reference["eligible_count"] == 0
            || unfillable.reference["no_eligible_maker"] == true
    );
}

fn eligible(audit_gates: bool, active: i128) -> (u64, String) {
    let directory = TestDir::new("oblivious-gates");
    let policies = directory.0.join("policies.json");
    let entries = (0..4)
        .map(|_| {
            format!(
                "{{\"asset\":0,\"ask_level\":10,\"spread\":5,\"slope\":1,\"invcoef\":0,\"inv\":0,\"maxqty\":900,\"expiry\":1000000000,\"active\":{active},\"use_ref\":1}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    fs::write(&policies, format!("[{entries}]\n")).unwrap();
    let input_dir = directory.0.join("inputs");
    let program = directory.0.join("q.mpc");
    let reference = directory.0.join("ref.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_qomm-gen"));
    command.args([
        "--n-mm",
        "4",
        "--policies",
        policies.to_str().unwrap(),
        "--out-program",
        program.to_str().unwrap(),
        "--out-input-dir",
        input_dir.to_str().unwrap(),
        "--out-reference",
        reference.to_str().unwrap(),
    ]);
    if audit_gates {
        command.arg("--audit-gates");
    }
    let output = command.output().expect("run qomm-gen");
    assert!(
        output.status.success(),
        "qomm-gen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_str(&fs::read_to_string(reference).unwrap()).unwrap();
    (
        value["eligible_count"].as_u64().unwrap(),
        fs::read_to_string(program).unwrap(),
    )
}

#[test]
fn a_withdrawn_maker_never_quotes_however_the_gates_are_configured() {
    for audit_gates in [false, true] {
        let (active_count, active_program) = eligible(audit_gates, 1);
        let (withdrawn_count, withdrawn_program) = eligible(audit_gates, 0);
        assert_eq!(active_count, 4);
        assert_eq!(
            withdrawn_count, 0,
            "a withdrawn maker was eligible with audit_gates={audit_gates}"
        );
        let active_gate = if audit_gates {
            "ok = active * g_asset * g_qty"
        } else {
            "ok = active * g_asset * g_qty * g_exp"
        };
        assert!(active_program.contains(active_gate));
        assert!(withdrawn_program.contains(active_gate));
    }
}
