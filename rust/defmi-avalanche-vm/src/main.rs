use std::{env, fs, io::Write, path::PathBuf, process::ExitCode};

use defmi_avalanche_vm::{genesis::GenesisConfig, id::vm_id, QommVm, VERSION};
mod recovery_cli;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qomm-avalanche-vm: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("version") if arguments.len() == 1 => println!("{VERSION}"),
        Some("vmid") if arguments.len() == 1 => println!("{}", vm_id()),
        Some("genesis") => genesis_command(&arguments[1..])?,
        Some("recovery") => recovery_cli::run(&arguments[1..])?,
        Some(_) => return Err("unknown command".into()),
        None => {
            avalanche_rpcchainvm_qomm::plugin::serve(QommVm::default())
                .await
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn genesis_command(arguments: &[String]) -> Result<(), String> {
    let mut config = None;
    let mut output = PathBuf::from("-");
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--config" if index + 1 < arguments.len() => {
                config = Some(PathBuf::from(&arguments[index + 1]));
                index += 2;
            }
            "--out" if index + 1 < arguments.len() => {
                output = PathBuf::from(&arguments[index + 1]);
                index += 2;
            }
            _ => {
                return Err("usage: qomm-avalanche-vm genesis --config FILE [--out FILE|-]".into())
            }
        }
    }
    let config = config.ok_or_else(|| {
        "usage: qomm-avalanche-vm genesis --config FILE [--out FILE|-]".to_string()
    })?;
    let metadata = fs::symlink_metadata(&config).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > (1 << 20) {
        return Err("genesis config must be a regular file containing 1..=1 MiB".into());
    }
    let raw = fs::read(&config).map_err(|error| error.to_string())?;
    let mut deserializer = serde_json::Deserializer::from_slice(&raw);
    let config =
        GenesisConfig::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    let encoded = config.into_genesis()?.encode()?;
    if output == std::path::Path::new("-") {
        std::io::stdout()
            .lock()
            .write_all(&encoded)
            .map_err(|error| error.to_string())?;
    } else {
        write_atomic(&output, &encoded)?;
    }
    Ok(())
}

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "output has no parent directory".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("genesis"),
        std::process::id()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

use serde::Deserialize;
