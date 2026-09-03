use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod defmi_cycle;

pub type HarnessResult<T> = Result<T, Box<dyn std::error::Error>>;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

pub fn unique_temp_dir(prefix: &str) -> io::Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path)?;
    Ok(path)
}

pub fn run_checked(command: &mut Command, what: &str) -> HarnessResult<Output> {
    // A program that is not installed fails here, not below, and the error the
    // operating system gives is `No such file or directory (os error 2)` --- the
    // same words it gives for a missing *input*. `make_figures` spent a whole
    // measurement run reporting that about `rsvg-convert`, which is present on
    // the laptop and absent on the host the measurements run on, and nothing in
    // the message said which of the two kinds of missing it meant.
    let output = command.output().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!(
                "{what}: the program `{}` is not installed or not on PATH",
                command.get_program().to_string_lossy()
            )
        } else {
            format!("{what}: {error}")
        }
    })?;
    if !output.status.success() {
        return Err(format!(
            "{what} failed with {}:\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}

pub fn write_pretty_json(path: Option<&Path>, value: &Value) -> HarnessResult<String> {
    let mut text = serde_json::to_string_pretty(value)?;
    if let Some(path) = path {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        text.push('\n');
        fs::write(path, &text)?;
        text.pop();
    }
    Ok(text)
}

pub fn next_value(
    args: &mut impl Iterator<Item = OsString>,
    name: &str,
) -> HarnessResult<OsString> {
    args.next()
        .ok_or_else(|| format!("argument {name} expects one value").into())
}

pub fn parse_value<T: std::str::FromStr>(raw: OsString, name: &str) -> HarnessResult<T>
where
    T::Err: std::fmt::Display,
{
    raw.into_string()
        .map_err(|_| format!("argument {name} is not valid UTF-8"))?
        .parse::<T>()
        .map_err(|error| format!("invalid {name}: {error}").into())
}

/// Return the first value from a legacy list-wrapped scalar artifact.
pub fn one(value: &Value) -> &Value {
    match value {
        Value::Array(values) => values.first().unwrap_or(&Value::Null),
        value => value,
    }
}

pub fn numeric(value: &Value) -> HarnessResult<f64> {
    value
        .as_f64()
        .ok_or_else(|| format!("expected a number, got {value}").into())
}

/// Return the single reading quoted from a measurement summary.
pub fn measurement_value(value: &Value) -> HarnessResult<f64> {
    if value.is_number() {
        return numeric(value);
    }
    if let Some(exact) = value.get("exact") {
        return numeric(exact);
    }
    value
        .get("mean")
        .ok_or_else(|| format!("measurement has no mean: {value}").into())
        .and_then(numeric)
}

fn fixed(value: f64, places: usize) -> String {
    format!("{value:.places$}")
}

/// Byte-compatible rendering for the measurement cells used by the generated
/// Markdown documents.
pub fn render_measurement(value: &Value, places: usize) -> HarnessResult<String> {
    if value.is_number() {
        return Ok(fixed(numeric(value)?, places));
    }
    if let Some(exact) = value.get("exact") {
        return Ok(format!("{} (exact)", value_display(exact)));
    }
    let n = value.get("n").and_then(Value::as_u64).unwrap_or(0);
    if n == 0 {
        return Ok("—".to_string());
    }
    let mean = numeric(&value["mean"])?;
    if value.get("sd").is_none_or(Value::is_null) {
        return Ok(format!("{} (n=1)", fixed(mean, places)));
    }
    Ok(format!(
        "{} ± {} (n={n})",
        fixed(mean, places),
        fixed(numeric(&value["sd"])?, places)
    ))
}

/// Render a JSON value compactly for human-readable reports. Top-level strings
/// are left unquoted; structured values use canonical JSON spelling.
pub fn value_display(value: &Value) -> String {
    if let Value::String(value) = value {
        return value.clone();
    }
    serde_json::to_string(value).expect("serde_json::Value always serializes")
}

pub fn comma_i64(value: i64) -> String {
    let negative = value < 0;
    let digits = value.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + usize::from(negative));
    if negative {
        out.push('-');
    }
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// The Rust compiler version that built the experiment harness.
pub fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// The mean `statistics.fmean` computes: `math.fsum` and one division.
///
/// helper standing for both is how a difference hides. `statistics.fmean` is
/// exactly rounded; the builtin `sum` carries a Neumaier term and is not. They
/// agree on most inputs, which is the problem.
pub fn fmean(values: &[f64]) -> Option<f64> {
    (!values.is_empty())
        .then(|| qomm_measure::fsum::fsum(values.iter().copied()) / values.len() as f64)
}

/// The mean `sum(values) / len(values)` computes, with the builtin's
/// compensation. See [`fmean`] for why the two are kept apart.
pub fn sum_mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty())
        .then(|| qomm_measure::fsum::nsum(values.iter().copied()) / values.len() as f64)
}

pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|left, right| left.total_cmp(right));
    let middle = ordered.len() / 2;
    Some(if ordered.len() % 2 == 1 {
        ordered[middle]
    } else {
        0.5 * (ordered[middle - 1] + ordered[middle])
    })
}

/// The two-pass sample standard deviation.
///
/// This is *not* `statistics.stdev`, which accumulates the sum of squared
/// deviations in exact rational arithmetic and takes one square root at the
/// end, and can therefore differ from this in the last place. Everything that
/// reaches it here is a duration, and durations are excluded from the
/// it would be the moment a non-timing value arrived.
pub fn sample_sd(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let mean = fmean(values)?;
    Some(
        (qomm_measure::fsum::fsum(values.iter().map(|value| (value - mean) * (value - mean)))
            / (values.len() - 1) as f64)
            .sqrt(),
    )
}

/// Say once, on stderr, that these durations came from an unoptimized build.
///
/// A wall-clock acceptance predicate compiled without optimisation describes the
/// build profile rather than the implementation: `run_three_times` reported
/// `audited_rfs_met <= 1000 ms` flipped on that alone. The Makefile builds every
/// measurement `--release`, so this only fires when something runs a binary out
/// of `target/debug` --- which is exactly the mistake that produced that number.
/// It goes to stderr rather than into the JSON so that the artifact shape stays
fn warn_once_if_unoptimized() {
    #[cfg(debug_assertions)]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            eprintln!(
                "warning: this is a debug build; every duration below describes \
                 the build profile, not the implementation. Build --release."
            );
        });
    }
}

pub fn timing_summary(values: &[f64]) -> Value {
    warn_once_if_unoptimized();
    let Some(mean) = fmean(values) else {
        return serde_json::json!({
            "n": 0, "mean": null, "sd": null, "median": null,
            "min": null, "max": null, "rsd": null,
        });
    };
    let sd = sample_sd(values);
    serde_json::json!({
        "n": values.len(),
        "mean": mean,
        "sd": sd,
        "median": median(values),
        "min": values.iter().copied().min_by(f64::total_cmp),
        "max": values.iter().copied().max_by(f64::total_cmp),
        "rsd": sd.filter(|_| mean != 0.0).map(|value| value / mean),
    })
}
