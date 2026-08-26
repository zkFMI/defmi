//! Rust port of `scripts/run_evm.py`.

use qomm_harness::{write_pretty_json, HarnessResult};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct Options {
    rpc: String,
    out: PathBuf,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> HarnessResult<()> {
    let options = parse_args()?;
    let root = qomm_harness::repo_root();
    let forge = Command::new("forge")
        .arg("test")
        .current_dir(root.join("evm"))
        .output()?;
    if !forge.status.success() {
        eprintln!("{}", tail(&String::from_utf8_lossy(&forge.stdout), 2_000));
        return Err(
            "forge test failed; the gas figure is only worth having if the implementation still matches the reference vectors."
                .into(),
        );
    }
    let gas_path = root.join("artifacts/evm_gas.json");
    if !gas_path.exists() {
        return Err(format!(
            "{} was not written; run `forge test` in evm/.",
            gas_path.display()
        )
        .into());
    }
    let gas: Value = serde_json::from_slice(&fs::read(&gas_path)?)?;
    let rust_path = root.join("artifacts/rust_bench.json");
    if !rust_path.exists() {
        return Err("artifacts/rust_bench.json is missing; run `make rust-bench` first --- the operation count comes from it.".into());
    }
    let rust: Value = serde_json::from_slice(&fs::read(&rust_path)?)?;
    let calibration = rust["calibration"]["scalar_mult_us"]
        .as_f64()
        .ok_or("rust_bench calibration.scalar_mult_us is missing")?;
    let (limit, used, height) = block_gas_limit(&options.rpc).map_err(|error| {
        format!(
            "no Ethereum node at {} ({}). The block gas limit is what decides whether this is expensive or impossible, so it is read rather than assumed: open a tunnel to an archive node and pass --rpc.",
            options.rpc, error
        )
    })?;
    let unit_gas = gas["gas"].as_f64().ok_or("evm_gas gas is missing")?;
    let mut rows = Vec::new();
    for row in rust["scaling"]
        .as_array()
        .ok_or("rust_bench scaling is not an array")?
    {
        let settle_ms = row["settle_ms"]
            .as_f64()
            .ok_or("rust_bench settle_ms is missing")?;
        let equivalents = settle_ms * 1_000.0 / calibration;
        let total = equivalents * unit_gas;
        rows.push(json!({
            "bits": row["bits"],
            "settle_ms": row["settle_ms"],
            "scalar_mult_equivalents": py_round_places(equivalents, 1),
            "gas": qomm_sim::market::py_round(total),
            "blocks": py_round_places(total / limit as f64, 2),
            "per_second_at_12s_blocks": py_round_places(limit as f64 / total / 12.0, 4),
        }));
    }
    let payload = json!({
        "host": rust["host"],
        "unit": gas,
        "operation_count_from": {
            "artifact": "rust_bench.json",
            "host": rust["host"],
            "scalar_mult_us": calibration,
            "note": "an equivalent count, from settle time over one scalar multiplication on the same machine. A floor: the verifier batches its terms and the EVM would not.",
        },
        "chain": {
            "network": "ethereum mainnet",
            "block": height,
            "gas_limit": limit,
            "gas_used": used,
        },
        "scaling": rows,
    });
    write_pretty_json(Some(&options.out), &payload)?;
    println!(
        "one scalar multiplication: {} gas",
        comma(gas["gas"].as_i64().unwrap_or(0))
    );
    println!(
        "block {}: limit {}, used {}",
        comma(height as i64),
        comma(limit as i64),
        comma(used as i64)
    );
    for row in payload["scaling"].as_array().into_iter().flatten() {
        println!(
            "  {:2} bits  {:6.1} scalar mults  {} gas  {:.2} blocks  {:.4} settlements/s",
            row["bits"].as_u64().unwrap_or(0),
            row["scalar_mult_equivalents"].as_f64().unwrap_or(0.0),
            comma(row["gas"].as_i64().unwrap_or(0)),
            row["blocks"].as_f64().unwrap_or(0.0),
            row["per_second_at_12s_blocks"].as_f64().unwrap_or(0.0),
        );
    }
    println!("wrote {}", options.out.display());
    Ok(())
}

fn block_gas_limit(rpc: &str) -> HarnessResult<(u64, u64, u64)> {
    let body =
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}"#;
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "-H",
            "Content-Type: application/json",
            "--data",
            body,
            rpc,
        ])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }
    let response: Value = serde_json::from_slice(&output.stdout)?;
    let result = response.get("result").ok_or("RPC result is missing")?;
    Ok((
        parse_hex(&result["gasLimit"])?,
        parse_hex(&result["gasUsed"])?,
        parse_hex(&result["number"])?,
    ))
}

fn parse_hex(value: &Value) -> HarnessResult<u64> {
    let text = value.as_str().ok_or("RPC hex value is not a string")?;
    Ok(u64::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

fn py_round_places(value: f64, places: i32) -> f64 {
    let scale = 10f64.powi(places);
    qomm_sim::market::py_round(value * scale) as f64 / scale
}

fn comma(value: i64) -> String {
    qomm_harness::comma_i64(value)
}

fn tail(text: &str, chars: usize) -> &str {
    let start = text
        .char_indices()
        .rev()
        .nth(chars.saturating_sub(1))
        .map_or(0, |(i, _)| i);
    &text[start..]
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options {
        rpc: "http://127.0.0.1:8545".into(),
        out: qomm_harness::repo_root().join("artifacts/evm_settlement.json"),
    };
    let raw = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < raw.len() {
        match raw[index].to_string_lossy().as_ref() {
            "--rpc" => {
                options.rpc = value(&raw, &mut index, "--rpc")?
                    .into_string()
                    .map_err(|_| "invalid --rpc")?
            }
            "--out" => options.out = PathBuf::from(value(&raw, &mut index, "--out")?),
            unknown => return Err(format!("unknown argument {unknown}").into()),
        }
        index += 1;
    }
    Ok(options)
}

fn value(raw: &[OsString], index: &mut usize, name: &str) -> HarnessResult<OsString> {
    *index += 1;
    raw.get(*index)
        .cloned()
        .ok_or_else(|| format!("{name} expects a value").into())
}
