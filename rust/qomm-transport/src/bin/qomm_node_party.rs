//! Execute one resident node's sealed slot as one stock MP-SPDZ party.

use qomm_transport::resident_mpc::{execute_resident_party, ResidentMpcConfig};
use qomm_transport::wire::FRAME_BYTES;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

const MAX_SEALED_STDIN: u64 = 28 + 4096 * (4 + FRAME_BYTES as u64);

struct Options {
    config: PathBuf,
    node: u16,
    slot: u32,
    batch_digest: [u8; 32],
    lane: usize,
    source_digest: String,
}

fn fixed_digest(value: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|_| format!("{name} must be a 32-byte hexadecimal digest"))?
        .try_into()
        .map_err(|_| format!("{name} must be a 32-byte hexadecimal digest"))
}

fn options() -> Result<Options, String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let value = |name: &str| -> Result<&str, String> {
        let index = arguments
            .iter()
            .position(|argument| argument == name)
            .ok_or_else(|| format!("missing {name}"))?;
        arguments
            .get(index + 1)
            .map(String::as_str)
            .ok_or_else(|| format!("{name} requires a value"))
    };
    Ok(Options {
        config: PathBuf::from(value("--config")?),
        node: value("--node")?
            .parse()
            .map_err(|_| "--node must be an unsigned 16-bit integer".to_string())?,
        slot: value("--slot")?
            .parse()
            .map_err(|_| "--slot must be an unsigned 32-bit integer".to_string())?,
        batch_digest: fixed_digest(value("--batch-digest")?, "--batch-digest")?,
        lane: value("--lane")?
            .parse()
            .map_err(|_| "--lane must be a non-negative integer".to_string())?,
        source_digest: value("--source-digest")?.to_string(),
    })
}

fn run() -> Result<(), String> {
    let options = options()?;
    let config: ResidentMpcConfig =
        serde_json::from_slice(&fs::read(&options.config).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if config.node != options.node {
        return Err("runtime configuration belongs to another node".into());
    }
    let mut sealed = Vec::new();
    io::stdin()
        .take(MAX_SEALED_STDIN + 1)
        .read_to_end(&mut sealed)
        .map_err(|error| error.to_string())?;
    if sealed.len() as u64 > MAX_SEALED_STDIN {
        return Err("sealed stdin exceeds the fixed-population bound".into());
    }
    let receipt = execute_resident_party(
        &config,
        options.slot,
        options.lane,
        options.batch_digest,
        &options.source_digest,
        &sealed,
    )?;
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|error| error.to_string())?
    );
    sealed.fill(0);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("qomm-node-party failed: {error}");
        std::process::exit(1);
    }
}
