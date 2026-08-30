//! Resident line-delimited JSON QOMM quoting service.

use qomm_transport::resident_quote::{
    load_approvals, serve, write_approvals, CircuitCache, QuoteResult,
};
use serde_json::Value;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct Options {
    host: String,
    port: u16,
    mp_spdz_root: PathBuf,
    warm: Option<Value>,
    approved: Option<PathBuf>,
    approve_into: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        let root = std::env::var_os("MP_SPDZ_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("work/qomm/MP-SPDZ")
            });
        Self {
            host: "127.0.0.1".into(),
            port: 8_899,
            mp_spdz_root: root,
            warm: None,
            approved: None,
            approve_into: None,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> QuoteResult<()> {
    let options = parse_args()?;
    let approvals = options
        .approved
        .as_deref()
        .map(load_approvals)
        .transpose()?;
    if let Some(entries) = &approvals {
        println!("{} approved shape(s) loaded", entries.len());
    }
    let workdir = unique_temp_dir("qomm-serve")?;
    let mut cache = CircuitCache::new(&options.mp_spdz_root, workdir, approvals)?;
    if let Some(request) = &options.warm {
        let compile_ms = cache.warm(request)?;
        println!("warmed one shape in {compile_ms:.1} ms");
    }
    if let Some(path) = &options.approve_into {
        let entries = cache.approval_entries();
        write_approvals(path, &entries)?;
        println!(
            "wrote {} approved shape(s) to {}",
            entries.len(),
            path.display()
        );
    }
    serve(cache, &options.host, options.port)
}

fn parse_args() -> QuoteResult<Options> {
    let raw = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut options = Options::default();
    let mut index = 0;
    while index < raw.len() {
        let argument = as_string(&raw[index], "argument")?;
        if argument == "-h" || argument == "--help" {
            println!("{}", usage());
            std::process::exit(0);
        }
        let (name, attached) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        let take = |index: &mut usize| -> QuoteResult<String> {
            if let Some(value) = attached {
                Ok(value.to_string())
            } else {
                *index += 1;
                raw.get(*index)
                    .ok_or_else(|| format!("argument {name} expects one value"))
                    .and_then(|value| as_string(value, name))
            }
        };
        match name {
            "--host" => options.host = take(&mut index)?,
            "--port" => {
                options.port = take(&mut index)?
                    .parse()
                    .map_err(|error| format!("invalid --port: {error}"))?
            }
            "--mp-spdz-root" => options.mp_spdz_root = PathBuf::from(take(&mut index)?),
            "--warm" => {
                options.warm = Some(
                    serde_json::from_str(&take(&mut index)?)
                        .map_err(|error| format!("invalid --warm JSON: {error}"))?,
                )
            }
            "--approved" => options.approved = Some(PathBuf::from(take(&mut index)?)),
            "--approve-into" => options.approve_into = Some(PathBuf::from(take(&mut index)?)),
            _ => return Err(format!("unknown argument {name}")),
        }
        index += 1;
    }
    Ok(options)
}

fn as_string(value: &OsString, name: &str) -> QuoteResult<String> {
    value
        .clone()
        .into_string()
        .map_err(|_| format!("{name} is not valid UTF-8"))
}

fn unique_temp_dir(prefix: &str) -> QuoteResult<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&path).map_err(|error| error.to_string())?;
    Ok(path)
}

fn usage() -> &'static str {
    "usage: serve_qomm [--host HOST] [--port PORT] [--mp-spdz-root PATH]\n\
     [--warm JSON] [--approved PATH] [--approve-into PATH]"
}
