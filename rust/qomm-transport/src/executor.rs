//! Allow-listed circuit execution for a resident MPC node.

use crate::resident_mpc::ResidentExecutionReceipt;
use qomm_dsl::registry::CircuitRegistry;
use qomm_mpc::program::{build_program, ProgramConfig};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub use qomm_mpc::persistence::{
    read as read_persisted_run, read_wires as read_persisted_wires, Error as PersistenceError,
    FieldElement as PersistedFieldElement, Persisted, Wires,
};

#[derive(Clone, Debug, Deserialize)]
pub struct RegisteredProgram {
    pub shape_digest: String,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub executable_sha256: String,
    /// Native stock-MP-SPDZ handoff used by a circuit-approved resident node.
    /// Isolated executor tests may omit it, but `from_approved_mpc` fails
    /// closed without this independently hashed runner and configuration.
    #[serde(default)]
    pub runtime: Option<RuntimeBinding>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: f64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeBinding {
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub config: PathBuf,
    pub config_sha256: String,
}

impl RuntimeBinding {
    fn verify(&self) -> Result<(), String> {
        verify_runtime_file(
            &self.executable,
            &self.executable_sha256,
            true,
            "resident MPC runner",
        )?;
        verify_runtime_file(
            &self.config,
            &self.config_sha256,
            false,
            "resident MPC configuration",
        )?;
        let mode = self
            .config
            .metadata()
            .map_err(|error| error.to_string())?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err("resident MPC configuration must use mode 600".into());
        }
        Ok(())
    }
}

fn verify_runtime_file(
    path: &Path,
    expected: &str,
    executable: bool,
    name: &str,
) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{name} must use an absolute path"));
    }
    let mut handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| format!("{name} is absent"))?;
    let metadata = handle.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || (executable && metadata.permissions().mode() & 0o111 == 0) {
        return Err(format!("{name} has the wrong file type or mode"));
    }
    let mut bytes = Vec::new();
    handle
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if hex::encode(Sha256::digest(bytes)) != expected {
        return Err(format!("{name} digest does not match its bytes"));
    }
    Ok(())
}

fn default_timeout() -> f64 {
    60.0
}

impl RegisteredProgram {
    pub fn verify(&self) -> Result<(), String> {
        self.open_verified(None).map(|_| ())
    }

    fn open_verified(&self, approved_digest: Option<&str>) -> Result<File, String> {
        let shape = hex::decode(&self.shape_digest)
            .map_err(|_| "shape digest must be a 32-byte hexadecimal digest")?;
        if shape.len() != 32 {
            return Err("shape digest must be a 32-byte hexadecimal digest".into());
        }
        let Some(executable) = self.argv.first().map(Path::new) else {
            return Err("registered executable must use an absolute path".into());
        };
        if !executable.is_absolute() {
            return Err("registered executable must use an absolute path".into());
        }
        let mut handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(executable)
            .map_err(|_| "registered executable is absent or not executable")?;
        let metadata = handle
            .metadata()
            .map_err(|_| "registered executable is absent or not executable")?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err("registered executable is absent or not executable".into());
        }
        let mut bytes = Vec::new();
        handle
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        handle
            .seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != self.executable_sha256 {
            return Err("registered executable digest does not match its bytes".into());
        }
        if approved_digest.is_some_and(|expected| expected != actual) {
            return Err("registered executable is not derived from the approved source".into());
        }
        if !self.cwd.is_dir() || !(0.0 < self.timeout_seconds && self.timeout_seconds <= 3600.0) {
            return Err("registered working directory or timeout is invalid".into());
        }
        if self.argv.iter().skip(1).any(|argument| {
            argument.contains('{')
                && argument != "{node}"
                && argument != "{slot}"
                && argument != "{batch_digest}"
                && argument != "{lane}"
        }) {
            return Err("only {node}, {slot}, and {batch_digest} placeholders are allowed".into());
        }
        if let Some(runtime) = &self.runtime {
            runtime.verify()?;
        }
        Ok(handle)
    }
}

/// Canonical executable bytes for the resident service's source-bound batch
/// runner.  The executable is a fixed, side-effect-free program whose only
/// variable byte is the digest of the exact qomm-mpc source approved by the DSL
/// registry.  Registration compares every byte, so an arbitrary command cannot
/// inherit approval by copying a digest into configuration.
pub fn source_bound_executable_bytes(source: &str) -> Vec<u8> {
    let source_digest = hex::encode(Sha256::digest(source.as_bytes()));
    format!(
        "#!/bin/sh\nset -eu\n\
         if [ \"$#\" -ne 3 ]; then exit 64; fi\n\
         source_digest='{source_digest}'\n\
         printf 'qomm-source=%s node=%s slot=%s batch=%s\\n' \\\n           \"$source_digest\" \"$1\" \"$2\" \"$3\"\n"
    )
    .into_bytes()
}

/// Canonical launcher for the real resident MPC runtime.
///
/// Its bytes commit to the approved circuit source, the exact runner binary,
/// and the exact non-secret runtime configuration. `ProgramRegistry` hashes
/// all three immediately before every launch; the launcher merely preserves
/// the already-verified paths while forwarding the sealed batch on stdin.
pub fn source_bound_runtime_executable_bytes(source: &str, runtime: &RuntimeBinding) -> Vec<u8> {
    let source_digest = hex::encode(Sha256::digest(source.as_bytes()));
    let runner = shell_quote(&runtime.executable.to_string_lossy());
    let config = shell_quote(&runtime.config.to_string_lossy());
    format!(
        concat!(
            "#!/bin/sh\n",
            "set -eu\n",
            "if [ \"$#\" -eq 3 ]; then lane=0; ",
            "elif [ \"$#\" -eq 4 ]; then lane=\"$4\"; else exit 64; fi\n",
            "source_digest='{source_digest}'\n",
            "# qomm-runtime-sha256={}\n",
            "# qomm-runtime-config-sha256={}\n",
            "exec {runner} --config {config} --node \"$1\" --slot \"$2\" \\\n",
            "  --batch-digest \"$3\" --lane \"$lane\" --source-digest \"$source_digest\"\n",
        ),
        runtime.executable_sha256,
        runtime.config_sha256,
        source_digest = source_digest,
        runner = runner,
        config = config,
    )
    .into_bytes()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Materialise the only executable form accepted for a DSL-approved source.
pub fn write_source_bound_executable(path: impl AsRef<Path>, source: &str) -> Result<(), String> {
    let path = path.as_ref();
    fs::write(path, source_bound_executable_bytes(source)).map_err(|error| error.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())
}

pub fn write_source_bound_runtime_executable(
    path: impl AsRef<Path>,
    source: &str,
    runtime: &RuntimeBinding,
) -> Result<(), String> {
    runtime.verify()?;
    let path = path.as_ref();
    fs::write(path, source_bound_runtime_executable_bytes(source, runtime))
        .map_err(|error| error.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())
}

fn command_from_verified_handle(
    executable: &File,
    argv: &[String],
    cwd: &Path,
    pipe_stdin: bool,
) -> Command {
    let descriptor = executable.as_raw_fd();
    // Resident programs are source-bound POSIX scripts. The trusted shell
    // reads the script through the inherited verified descriptor, so the
    // executable pathname is never reopened after hashing.
    let mut command = Command::new("/bin/sh");
    command
        .arg(format!("/dev/fd/{descriptor}"))
        .args(&argv[1..])
        .current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(if pipe_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: this runs after fork and before exec in the child. Clearing
    // FD_CLOEXEC on the already-open verified descriptor is async-signal-safe
    // and makes /dev/fd/N name the exact bytes hashed above.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

#[derive(Clone, Debug)]
pub struct SealedExecution {
    pub slot: u32,
    pub batch_digest: [u8; 32],
    pub frames: Vec<Vec<u8>>,
}

impl SealedExecution {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"QOMM:SEALED:BATCH:v1");
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.frames.len())
                .map_err(|_| "sealed batch contains too many frames".to_string())?
                .to_be_bytes(),
        );
        for frame in &self.frames {
            bytes.extend_from_slice(
                &u32::try_from(frame.len())
                    .map_err(|_| "sealed frame is too large".to_string())?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(frame);
        }
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != self.batch_digest {
            return Err("sealed batch digest does not match the stored frames".into());
        }
        Ok(bytes)
    }
}

#[derive(Deserialize)]
struct RegistryFile {
    #[serde(default)]
    programs: Vec<RegisteredProgram>,
    approval: Option<ApprovalFile>,
}

#[derive(Deserialize)]
struct ApprovalFile {
    name: String,
    rule_source_file: PathBuf,
    program_source_file: PathBuf,
    shape: Vec<u64>,
    program_config: ProgramConfig,
}

#[derive(Debug)]
pub struct ProgramRegistry {
    node: u16,
    programs: BTreeMap<String, RegisteredProgram>,
    approved_executable_digests: BTreeMap<String, String>,
    approved_source_digests: BTreeMap<String, String>,
    circuit_approved: bool,
    execution_count: AtomicU64,
}

impl ProgramRegistry {
    pub fn new(node: u16, programs: Vec<RegisteredProgram>) -> Result<Self, String> {
        let mut approved = BTreeMap::new();
        for program in programs {
            program.verify()?;
            if approved
                .insert(program.shape_digest.clone(), program)
                .is_some()
            {
                return Err("duplicate registered shape digest".into());
            }
        }
        Ok(Self {
            node,
            programs: approved,
            approved_executable_digests: BTreeMap::new(),
            approved_source_digests: BTreeMap::new(),
            circuit_approved: false,
            execution_count: AtomicU64::new(0),
        })
    }

    /// Construct the registry used by a resident node.
    ///
    /// The exact program is generated by `qomm-mpc`, checked against the
    /// venue's `qomm-dsl` circuit registry, and bound to the request's shape
    /// digest.  [`Self::new`] remains available for the executor's isolated
    /// byte-verification tests, but a node service refuses such an unbound
    /// registry.
    pub fn from_approved_mpc(
        node: u16,
        program: RegisteredProgram,
        registry: &CircuitRegistry,
        config: &ProgramConfig,
        shape: &[u64],
    ) -> Result<Self, String> {
        let source = build_program(config).map_err(|error| error.to_string())?;
        registry.check(&source, shape)?;
        let expected = circuit_shape_digest(shape);
        if program.shape_digest != expected {
            return Err(format!(
                "registered shape digest {} does not identify the approved circuit shape {expected}",
                program.shape_digest
            ));
        }
        let mut approved = Self::new(node, vec![program])?;
        approved.bind_approved_source(&source)?;
        approved.circuit_approved = true;
        Ok(approved)
    }

    pub fn is_circuit_approved(&self) -> bool {
        self.circuit_approved
    }

    pub fn execution_count(&self) -> u64 {
        self.execution_count.load(Ordering::Acquire)
    }

    pub fn from_json(node: u16, path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let raw = fs::read(path).map_err(|error| error.to_string())?;
        let file: RegistryFile = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
        let mut programs = Self::new(node, file.programs)?;
        if let Some(approval) = file.approval {
            let base = path.parent().unwrap_or_else(|| Path::new("."));
            let rule_source = fs::read_to_string(base.join(approval.rule_source_file))
                .map_err(|error| error.to_string())?;
            let program_source = fs::read_to_string(base.join(approval.program_source_file))
                .map_err(|error| error.to_string())?;
            let expected_source =
                build_program(&approval.program_config).map_err(|error| error.to_string())?;
            if program_source != expected_source {
                return Err(
                    "approved MPC source is not the exact output of the Rust generator configuration"
                        .into(),
                );
            }
            let expected_shape = vec![
                approval.program_config.n_mm as u64,
                approval.program_config.n_parties as u64,
                u64::from(approval.program_config.bit_length),
            ];
            if approval.shape != expected_shape {
                return Err(format!(
                    "approved circuit shape {:?} does not match generator configuration {:?}",
                    approval.shape, expected_shape
                ));
            }
            let mut circuits = CircuitRegistry::default();
            circuits
                .approve(
                    &approval.name,
                    &rule_source,
                    &program_source,
                    &approval.shape,
                )
                .map_err(|error| error.to_string())?;
            circuits.check(&program_source, &approval.shape)?;
            let expected = circuit_shape_digest(&approval.shape);
            if programs
                .programs
                .keys()
                .any(|shape_digest| shape_digest != &expected)
            {
                return Err(format!(
                    "registered shape digest does not identify the approved circuit shape {expected}"
                ));
            }
            programs.bind_approved_source(&program_source)?;
            programs.circuit_approved = true;
        }
        Ok(programs)
    }

    fn bind_approved_source(&mut self, source: &str) -> Result<(), String> {
        let source_digest = hex::encode(Sha256::digest(source.as_bytes()));
        for (shape, program) in &self.programs {
            if !(program.argv.len() == 4 || program.argv.len() == 5)
                || program.argv[1] != "{node}"
                || program.argv[2] != "{slot}"
                || program.argv[3] != "{batch_digest}"
                || program.argv.get(4).is_some_and(|value| value != "{lane}")
            {
                return Err(
                    "approved executables must accept {node}, {slot}, {batch_digest}, and optionally {lane}"
                        .into(),
                );
            }
            let runtime = program.runtime.as_ref().ok_or_else(|| {
                "circuit-approved computation has no hashed resident MPC runtime".to_string()
            })?;
            runtime.verify()?;
            let expected_bytes = source_bound_runtime_executable_bytes(source, runtime);
            let expected_digest = hex::encode(Sha256::digest(&expected_bytes));
            program.open_verified(Some(&expected_digest))?;
            self.approved_executable_digests
                .insert(shape.clone(), expected_digest.clone());
            self.approved_source_digests
                .insert(shape.clone(), source_digest.clone());
        }
        Ok(())
    }

    pub fn execute(&self, request: &Value) -> Result<Value, String> {
        self.execute_inner(request, None)
    }

    pub fn execute_sealed(
        &self,
        request: &Value,
        sealed: &SealedExecution,
    ) -> Result<Value, String> {
        self.execute_inner(request, Some(sealed))
    }

    fn execute_inner(
        &self,
        request: &Value,
        sealed: Option<&SealedExecution>,
    ) -> Result<Value, String> {
        let shape = request
            .get("shape_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| "shape is not in the approved program registry".to_string())?;
        let program = self
            .programs
            .get(shape)
            .ok_or_else(|| "shape is not in the approved program registry".to_string())?;
        if self.circuit_approved && sealed.is_none() {
            return Err("approved computation requires a sealed stored batch".into());
        }
        let approved_digest = self
            .approved_executable_digests
            .get(shape)
            .map(String::as_str);
        // Open once, hash this handle, and execute through the same inherited
        // descriptor. Replacing the pathname after this point changes neither
        // the verified bytes nor the bytes exec observes.
        let executable = program.open_verified(approved_digest)?;
        let slot = if let Some(sealed) = sealed {
            if request.get("slot").and_then(Value::as_u64) != Some(u64::from(sealed.slot)) {
                return Err("sealed batch belongs to another computation slot".into());
            }
            u64::from(sealed.slot)
        } else {
            request
                .get("slot")
                .and_then(Value::as_u64)
                .filter(|slot| *slot < (1_u64 << 63))
                .ok_or_else(|| "computation slot is invalid".to_string())?
        };
        let batch_digest = sealed
            .map(|batch| hex::encode(batch.batch_digest))
            .unwrap_or_default();
        let lane = if let Some(sealed) = sealed {
            let lane = request.get("lane").and_then(Value::as_u64).unwrap_or(0);
            if lane >= sealed.frames.len() as u64 {
                return Err("computation lane is outside the fixed population".into());
            }
            lane
        } else {
            request.get("lane").and_then(Value::as_u64).unwrap_or(0)
        };
        let argv = program
            .argv
            .iter()
            .map(|argument| {
                argument
                    .replace("{node}", &self.node.to_string())
                    .replace("{slot}", &slot.to_string())
                    .replace("{batch_digest}", &batch_digest)
                    .replace("{lane}", &lane.to_string())
            })
            .collect::<Vec<_>>();
        let started = Instant::now();
        self.execution_count.fetch_add(1, Ordering::AcqRel);
        let mut child =
            command_from_verified_handle(&executable, &argv, &program.cwd, sealed.is_some())
                .spawn()
                .map_err(|error| format!("approved computation failed to start: {error}"))?;
        if let Some(sealed) = sealed {
            let input = sealed.encode()?;
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| "approved computation stdin was not captured".to_string())?;
            stdin.write_all(&input).map_err(|error| error.to_string())?;
        }
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| "approved computation stdout was not captured".to_string())?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| "approved computation stderr was not captured".to_string())?;
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        let timeout = Duration::from_secs_f64(program.timeout_seconds);
        loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                let _ = child.wait();
                let stdout = stdout_reader
                    .join()
                    .map_err(|_| "approved computation stdout reader panicked".to_string())?
                    .map_err(|error| error.to_string())?;
                let stderr = stderr_reader
                    .join()
                    .map_err(|_| "approved computation stderr reader panicked".to_string())?
                    .map_err(|error| error.to_string())?;
                if !status.success() {
                    // The approved child can see sealed inputs, so its raw output must
                    // never cross the node boundary on failure.  Still return enough
                    // immutable evidence for operators to correlate failures across
                    // the seven parties.  The previous generic error claimed that
                    // digests were retained but discarded the digests themselves.
                    return Err(format!(
                        "approved computation failed (exit_code={}, stdout_digest={}, stderr_digest={}); raw output was not disclosed",
                        status.code().unwrap_or(-1),
                        hex::encode(Sha256::digest(&stdout)),
                        hex::encode(Sha256::digest(&stderr)),
                    ));
                }
                let mut response = json!({
                    "slot": slot,
                    "shape_digest": shape,
                    "exit_code": status.code().unwrap_or(0),
                    "elapsed_ns": started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                    "stdout_digest": hex::encode(Sha256::digest(&stdout)),
                    "stderr_digest": hex::encode(Sha256::digest(&stderr)),
                    "batch_digest": batch_digest,
                    "lane": lane,
                });
                if self.circuit_approved {
                    let receipt: ResidentExecutionReceipt = serde_json::from_slice(&stdout)
                        .map_err(|_| {
                            "approved resident MPC runner returned a malformed execution receipt"
                                .to_string()
                        })?;
                    let expected_batch = sealed
                        .map(|value| value.batch_digest)
                        .ok_or_else(|| "approved execution lost its sealed batch".to_string())?;
                    let expected_source = self
                        .approved_source_digests
                        .get(shape)
                        .ok_or_else(|| "approved execution lost its source digest".to_string())?;
                    receipt.validate_against(
                        self.node,
                        u32::try_from(slot)
                            .map_err(|_| "approved execution slot is outside u32".to_string())?,
                        usize::try_from(lane)
                            .map_err(|_| "approved execution lane is outside usize".to_string())?,
                        expected_batch,
                        expected_source,
                    )?;
                    let object = response
                        .as_object_mut()
                        .expect("executor response is constructed as an object");
                    object.insert(
                        "mpc_execution_digest".into(),
                        Value::String(hex::encode(receipt.public_digest()?)),
                    );
                    object.insert(
                        "mpc_source_digest".into(),
                        Value::String(receipt.source_digest.clone()),
                    );
                    object.insert(
                        "mpc_persistence_digest".into(),
                        Value::String(hex::encode(receipt.persistence_digest)),
                    );
                    object.insert(
                        "mpc_stdout_digest".into(),
                        Value::String(hex::encode(receipt.stdout_digest)),
                    );
                    object.insert(
                        "mpc_stderr_digest".into(),
                        Value::String(hex::encode(receipt.stderr_digest)),
                    );
                    object.insert(
                        "mpc_state_generation".into(),
                        Value::from(receipt.state_generation),
                    );
                    object.insert(
                        "mpc_frame_count".into(),
                        Value::from(receipt.frame_count as u64),
                    );
                    object.insert(
                        "mpc_input_count".into(),
                        Value::from(receipt.input_count as u64),
                    );
                }
                return Ok(response);
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err("approved computation exceeded its timeout".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Stable request identifier for the public circuit shape.
pub fn circuit_shape_digest(shape: &[u64]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"QOMM:CIRCUIT:SHAPE:v1");
    digest.update((shape.len() as u64).to_be_bytes());
    for dimension in shape {
        digest.update(dimension.to_be_bytes());
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_handle_survives_path_replacement_before_spawn() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("program.sh");
        let replacement = directory.path().join("replacement.sh");
        fs::write(&executable, b"#!/bin/sh\nprintf 'verified\\n'\n").unwrap();
        fs::write(&replacement, b"#!/bin/sh\nprintf 'replaced\\n'\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        let program = RegisteredProgram {
            shape_digest: "01".repeat(32),
            argv: vec![executable.display().to_string()],
            cwd: directory.path().to_path_buf(),
            executable_sha256: hex::encode(Sha256::digest(fs::read(&executable).unwrap())),
            runtime: None,
            timeout_seconds: 5.0,
        };
        let verified = program.open_verified(None).unwrap();
        fs::rename(&replacement, &executable).unwrap();

        let output = command_from_verified_handle(&verified, &program.argv, &program.cwd, false)
            .output()
            .unwrap();
        // Not `assert!(output.status.success())`: that told us nothing the one
        // time it fired under a full parallel run on macOS. See REVIEW.md 28.
        assert!(
            output.status.success(),
            "status={:?} stdout={:?} stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"verified\n");
    }
}
