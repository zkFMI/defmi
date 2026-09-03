//! Compile-once QOMM quote execution and the line-delimited JSON service.
//!
//! Program and input generation use `qomm-mpc`; only the MP-SPDZ compiler and
//! stock party binary remain external, because those are the implementation
//! whose protocol cost the measurement harness is intended to measure.

use qomm_dsl::registry::program_digest;
use qomm_mpc::compiler::OfficialCompiler;
use qomm_mpc::inputs::{build_inputs, finish_reference, parse_policies, InputConfig};
use qomm_mpc::program::{
    build_program, pow2_ceil, sentinel_for, CheckMode, Disclosure, Mode, ProgramConfig,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub type QuoteResult<T> = Result<T, String>;

const SHAPE: [&str; 15] = [
    "n_mm",
    "n_parties",
    "mode",
    "rfs_steps",
    "disclose",
    "bit_length",
    "argmin_arity",
    "n_assets",
    "n_requests",
    "edabit",
    "audit_gates",
    "public_maker_assets",
    "input_check",
    "threshold",
    "ref_table",
];

#[derive(Clone, Debug)]
struct Request {
    n_mm: usize,
    n_parties: usize,
    mode: Mode,
    rfs_steps: usize,
    disclose: Disclosure,
    bit_length: u32,
    argmin_arity: usize,
    n_assets: usize,
    n_requests: usize,
    edabit: bool,
    audit_gates: bool,
    public_maker_assets: bool,
    input_check: bool,
    threshold: usize,
    user_qty: i128,
    user_dir: i128,
    user_asset: usize,
    seed: i128,
    is_real: i128,
    delay_ms: f64,
    policies: Option<Value>,
    ref_table: Option<Vec<i128>>,
}

impl Request {
    fn from_value(value: &Value) -> QuoteResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| "request must be a JSON object".to_string())?;
        let defaults = ProgramConfig::default();
        let mode_name = string(object, "mode", defaults.mode.as_str())?;
        let disclose_name = string(object, "disclose", defaults.disclose.as_str())?;
        let input_check = bool_field(object, "input_check", true)?;
        if !input_check {
            return Err(
                "resident quote service refuses unchecked MPC inputs; use the measurement harness for unchecked experiments"
                    .into(),
            );
        }
        Ok(Self {
            n_mm: usize_field(object, "n_mm", defaults.n_mm)?,
            n_parties: usize_field(object, "n_parties", defaults.n_parties)?,
            mode: Mode::parse(&mode_name)
                .ok_or_else(|| "mode must be rfq, rfm, or rfs".to_string())?,
            rfs_steps: usize_field(object, "rfs_steps", defaults.rfs_steps)?,
            disclose: Disclosure::parse(&disclose_name)
                .ok_or_else(|| "disclose must be none or threshold".to_string())?,
            // The resident service intentionally differs from ProgramConfig's
            // direct library default here, so this is the service contract's default.
            bit_length: u32_field(object, "bit_length", 31)?,
            argmin_arity: usize_field(object, "argmin_arity", defaults.argmin_arity)?,
            n_assets: usize_field(object, "n_assets", defaults.n_assets)?,
            n_requests: usize_field(object, "n_requests", defaults.n_requests)?,
            edabit: bool_field(object, "edabit", defaults.edabit)?,
            audit_gates: bool_field(object, "audit_gates", defaults.audit_gates)?,
            public_maker_assets: bool_field(
                object,
                "public_maker_assets",
                defaults.public_maker_assets,
            )?,
            input_check,
            threshold: usize_field(object, "threshold", 2)?,
            user_qty: i128_field(object, "user_qty", 100)?,
            user_dir: i128_field(object, "user_dir", 0)?,
            user_asset: usize_field(object, "user_asset", 0)?,
            seed: i128_field(object, "seed", 7)?,
            is_real: i128_field(object, "is_real", 1)?,
            delay_ms: f64_field(object, "delay_ms", 0.0)?,
            policies: object
                .get("policies")
                .filter(|value| !value.is_null())
                .cloned(),
            ref_table: optional_i128_array(object.get("ref_table"))?,
        })
    }

    fn shape(&self) -> Value {
        let mut values = Map::new();
        values.insert("n_mm".into(), json!(self.n_mm));
        values.insert("n_parties".into(), json!(self.n_parties));
        values.insert("mode".into(), json!(self.mode.as_str()));
        values.insert("rfs_steps".into(), json!(self.rfs_steps));
        values.insert("disclose".into(), json!(self.disclose.as_str()));
        values.insert("bit_length".into(), json!(self.bit_length));
        values.insert("argmin_arity".into(), json!(self.argmin_arity));
        values.insert("n_assets".into(), json!(self.n_assets));
        values.insert("n_requests".into(), json!(self.n_requests));
        values.insert("edabit".into(), json!(self.edabit));
        values.insert("audit_gates".into(), json!(self.audit_gates));
        values.insert(
            "public_maker_assets".into(),
            json!(self.public_maker_assets),
        );
        values.insert("input_check".into(), json!(self.input_check));
        values.insert("threshold".into(), json!(self.threshold));
        values.insert(
            "ref_table".into(),
            self.ref_table
                .as_ref()
                .map_or(Value::Null, |table| json!(table)),
        );
        Value::Array(
            SHAPE
                .iter()
                .map(|name| json!([name, values[*name].clone()]))
                .collect(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct Approval {
    name: String,
    program_digest: String,
    shape: Value,
}

impl Approval {
    pub fn from_json(value: &Value) -> QuoteResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| "each approved circuit must be an object".to_string())?;
        Ok(Self {
            name: required_string(object, "name")?,
            program_digest: required_string(object, "program_digest")?,
            shape: object
                .get("shape")
                .cloned()
                .ok_or_else(|| "approved circuit is missing shape".to_string())?,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Quote {
    pub verified: bool,
    pub detail: String,
    pub protocol_ms: f64,
    pub wall_ms: f64,
    pub rounds: Option<u64>,
    pub mb: Option<f64>,
    pub compiled_once_ms: f64,
    pub served_by_shape: usize,
}

struct Generated {
    source: String,
    inputs: Vec<String>,
    reference: Value,
}

struct Execution {
    ok: bool,
    wall_seconds: f64,
    party0_seconds: Option<f64>,
    party0_mb: Option<f64>,
    party0_rounds: Option<u64>,
    log: String,
}

struct Shape {
    request: Request,
    shape: Value,
    program: String,
    source: String,
    compile_ms: f64,
    served: usize,
    run_dir: PathBuf,
    port_base: Option<u16>,
}

/// One compiled MP-SPDZ circuit per request shape.
pub struct CircuitCache {
    compiler: OfficialCompiler,
    root: PathBuf,
    workdir: PathBuf,
    shapes: Vec<Shape>,
    shape_indexes: HashMap<String, usize>,
    approvals: Option<Vec<Approval>>,
    saved_inputs: HashMap<PathBuf, Option<Vec<u8>>>,
    next_run_id: u64,
}

impl CircuitCache {
    pub fn new(
        root: impl AsRef<Path>,
        workdir: impl AsRef<Path>,
        approvals: Option<Vec<Approval>>,
    ) -> QuoteResult<Self> {
        let compiler =
            OfficialCompiler::from_checkout(root.as_ref()).map_err(|error| error.to_string())?;
        let root = compiler.root().to_path_buf();
        if !root.join("malicious-shamir-party.x").is_file() {
            return Err(format!(
                "{} is missing malicious-shamir-party.x",
                root.display()
            ));
        }
        fs::create_dir_all(workdir.as_ref()).map_err(|error| error.to_string())?;
        Ok(Self {
            compiler,
            root,
            workdir: workdir.as_ref().to_path_buf(),
            shapes: Vec::new(),
            shape_indexes: HashMap::new(),
            approvals,
            saved_inputs: HashMap::new(),
            next_run_id: 0,
        })
    }

    pub fn warm(&mut self, request: &Value) -> QuoteResult<f64> {
        let request = Request::from_value(request)?;
        let index = self.ensure_shape(&request)?;
        Ok(self.shapes[index].compile_ms)
    }

    pub fn compile_ms(&self, request: &Value) -> QuoteResult<f64> {
        let request = Request::from_value(request)?;
        let key = serde_json::to_string(&request.shape()).map_err(|error| error.to_string())?;
        self.shape_indexes
            .get(&key)
            .map(|index| self.shapes[*index].compile_ms)
            .ok_or_else(|| "shape is not resident".to_string())
    }

    pub fn quote(&mut self, request: &Value) -> QuoteResult<Quote> {
        let request = Request::from_value(request)?;
        let index = self.ensure_shape(&request)?;
        let generated = generate(&request)?;
        self.install_inputs(&generated.inputs)?;
        let execution = {
            let shape = &mut self.shapes[index];
            shape.execute(&self.root, request.delay_ms)?
        };
        if !execution.ok {
            return Err("a party failed".into());
        }
        let (verified, detail) = verify(request.mode, &execution.log, &generated.reference)?;
        let shape = &mut self.shapes[index];
        shape.served += 1;
        Ok(Quote {
            verified,
            detail,
            protocol_ms: execution.party0_seconds.unwrap_or(0.0) * 1_000.0,
            wall_ms: execution.wall_seconds * 1_000.0,
            rounds: execution.party0_rounds,
            mb: execution.party0_mb,
            compiled_once_ms: shape.compile_ms,
            served_by_shape: shape.served,
        })
    }

    pub fn approval_entries(&self) -> Vec<Value> {
        self.shapes
            .iter()
            .enumerate()
            .map(|(index, shape)| {
                json!({
                    "name": format!("shape{index}"),
                    "program_digest": program_digest(&shape.source),
                    "shape": shape.shape,
                })
            })
            .collect()
    }

    fn ensure_shape(&mut self, request: &Request) -> QuoteResult<usize> {
        let shape_value = request.shape();
        let key = serde_json::to_string(&shape_value).map_err(|error| error.to_string())?;
        if let Some(index) = self.shape_indexes.get(&key) {
            return Ok(*index);
        }
        let generated = generate(request)?;
        if let Some(approvals) = &self.approvals {
            let approval = approvals
                .iter()
                .find(|entry| entry.shape == shape_value)
                .ok_or_else(|| format!("refusing to compile this circuit: no circuit is approved for shape {shape_value}"))?;
            let actual = program_digest(&generated.source);
            if actual != approval.program_digest {
                return Err(format!(
                    "refusing to compile this circuit: the program for {} does not match what was approved: {} against {}",
                    approval.name,
                    &actual[..16],
                    &approval.program_digest[..approval.program_digest.len().min(16)]
                ));
            }
        }
        self.install_inputs(&generated.inputs)?;
        let index = self.shapes.len();
        let program = format!(
            "qomm_serve_{}_{}_{}",
            std::process::id(),
            self.next_run_id,
            index
        );
        self.next_run_id += 1;
        let source_dest = self
            .root
            .join("Programs/Source")
            .join(format!("{program}.mpc"));
        fs::create_dir_all(
            source_dest
                .parent()
                .ok_or_else(|| "program source has no parent".to_string())?,
        )
        .map_err(|error| error.to_string())?;
        fs::write(&source_dest, &generated.source).map_err(|error| error.to_string())?;
        let started = Instant::now();
        let output = self
            .compiler
            .compile_field(128, &program)
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let _ = fs::remove_file(&source_dest);
            return Err(format!("compile failed:\n{}", tail(&combined, 4_000)));
        }
        let run_dir = self.workdir.join(format!("run-{index}"));
        fs::create_dir_all(&run_dir).map_err(|error| error.to_string())?;
        self.shapes.push(Shape {
            request: request.clone(),
            shape: shape_value,
            program,
            source: generated.source,
            compile_ms: started.elapsed().as_secs_f64() * 1_000.0,
            served: 0,
            run_dir,
            port_base: None,
        });
        self.shape_indexes.insert(key, index);
        Ok(index)
    }

    fn install_inputs(&mut self, inputs: &[String]) -> QuoteResult<()> {
        let player_data = self.root.join("Player-Data");
        fs::create_dir_all(&player_data).map_err(|error| error.to_string())?;
        for (party, contents) in inputs.iter().enumerate() {
            let target = player_data.join(format!("Input-P{party}-0"));
            if !self.saved_inputs.contains_key(&target) {
                self.saved_inputs
                    .insert(target.clone(), fs::read(&target).ok());
            }
            fs::write(&target, contents).map_err(|error| error.to_string())?;
            let output = player_data.join(format!("Private-Output-P{party}"));
            if output.exists() {
                fs::remove_file(output).map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }
}

impl Drop for CircuitCache {
    fn drop(&mut self) {
        for (target, saved) in self.saved_inputs.drain() {
            if let Some(bytes) = saved {
                let _ = fs::write(target, bytes);
            } else {
                let _ = fs::remove_file(target);
            }
        }
        for shape in &self.shapes {
            let _ = fs::remove_file(
                self.root
                    .join("Programs/Source")
                    .join(format!("{}.mpc", shape.program)),
            );
            let _ = fs::remove_file(
                self.root
                    .join("Programs/Schedules")
                    .join(format!("{}.sch", shape.program)),
            );
            let _ = fs::remove_file(self.root.join("Programs/Public-Input").join(&shape.program));
            remove_matching(
                &self.root.join("Programs/Bytecode"),
                &format!("{}-", shape.program),
                ".bc",
            );
        }
        let _ = fs::remove_dir_all(&self.workdir);
    }
}

impl Shape {
    fn execute(&mut self, root: &Path, delay_ms: f64) -> QuoteResult<Execution> {
        let n = self.request.n_parties;
        let count = n * (n + 2);
        let actual_base = *self
            .port_base
            .get_or_insert_with(|| free_port_block(count, 21_000));
        let proxy_base = actual_base + n as u16 + 1;
        let proxies = self.write_host_files(actual_base, proxy_base, delay_ms)?;
        let mut proxy = if proxies.is_empty() {
            None
        } else {
            Some(start_proxy(&self.run_dir, delay_ms, &proxies)?)
        };
        let started = Instant::now();
        let mut children = Vec::with_capacity(n);
        for party in 0..n {
            let log_path = self.run_dir.join(format!("party-{party}.log"));
            let log = File::create(&log_path).map_err(|error| error.to_string())?;
            let stderr = log.try_clone().map_err(|error| error.to_string())?;
            let child = Command::new(root.join("malicious-shamir-party.x"))
                .current_dir(root)
                .arg(party.to_string())
                .arg(&self.program)
                .args([
                    "-N",
                    &n.to_string(),
                    "-T",
                    &self.request.threshold.to_string(),
                ])
                .arg("-ip")
                .arg(self.run_dir.join(format!("hosts-P{party}")))
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(stderr))
                .spawn()
                .map_err(|error| format!("party {party} did not start: {error}"))?;
            children.push(child);
        }
        let ok = wait_all(&mut children, Duration::from_secs(1_800))?;
        let wall_seconds = started.elapsed().as_secs_f64();
        if let Some(child) = proxy.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let logs = (0..n)
            .map(|party| {
                fs::read_to_string(self.run_dir.join(format!("party-{party}.log")))
                    .map_err(|error| error.to_string())
            })
            .collect::<QuoteResult<Vec<_>>>()?;
        let combined = logs
            .iter()
            .enumerate()
            .map(|(party, log)| format!("===== PARTY {party} =====\n{log}"))
            .collect::<Vec<_>>()
            .join("\n");
        let party0 = logs.first().map(String::as_str).unwrap_or("");
        let (party0_mb, party0_rounds) = parse_data_sent(party0).unwrap_or((None, None));
        Ok(Execution {
            ok,
            wall_seconds,
            party0_seconds: parse_seconds(party0),
            party0_mb,
            party0_rounds,
            log: combined,
        })
    }

    fn write_host_files(
        &self,
        actual_base: u16,
        proxy_base: u16,
        delay_ms: f64,
    ) -> QuoteResult<Vec<Value>> {
        let n = self.request.n_parties;
        let mut proxies = Vec::new();
        for source in 0..n {
            let mut lines = String::new();
            for target in 0..n {
                let port = if delay_ms == 0.0 || source == target {
                    actual_base + target as u16
                } else {
                    let port = proxy_base + (source * n + target) as u16;
                    proxies.push(json!({
                        "source": source,
                        "target": target,
                        "listen_port": port,
                        "target_port": actual_base + target as u16,
                        "one_way_delay_ms": delay_ms,
                    }));
                    port
                };
                lines.push_str(&format!("127.0.0.1:{port}\n"));
            }
            fs::write(self.run_dir.join(format!("hosts-P{source}")), lines)
                .map_err(|error| error.to_string())?;
        }
        Ok(proxies)
    }
}

fn generate(request: &Request) -> QuoteResult<Generated> {
    let padded = pow2_ceil(request.n_mm).map_err(|error| error.to_string())?;
    if request.n_assets == 0 {
        return Err("n_assets must be positive".into());
    }
    if request.user_asset >= request.n_assets {
        return Err("user_asset must be below n_assets".into());
    }
    let defaults = ProgramConfig::default();
    let ref_table = request.ref_table.clone().unwrap_or_else(|| {
        (0..request.n_assets)
            .map(|asset| defaults.ref_mid + 5_000 * asset as i128)
            .collect()
    });
    if ref_table.len() != request.n_assets {
        return Err(format!(
            "ref_table has {} entries for {} assets",
            ref_table.len(),
            request.n_assets
        ));
    }
    let max_ref = *ref_table
        .iter()
        .max()
        .ok_or_else(|| "ref_table must contain at least one entry".to_string())?;
    let sentinel =
        sentinel_for(request.bit_length, padded, 8 * max_ref).map_err(|error| error.to_string())?;
    // This is gen_qomm's CLI default, which differs from ProgramConfig's
    // direct-call default even when input checking is disabled.
    let config = ProgramConfig {
        n_mm: padded,
        n_parties: request.n_parties,
        mode: request.mode,
        rfs_steps: request.rfs_steps,
        disclose: request.disclose,
        n_requests: request.n_requests,
        n_assets: request.n_assets,
        ref_table: ref_table.clone(),
        maker_assets: (0..padded).map(|maker| maker % request.n_assets).collect(),
        public_maker_assets: request.public_maker_assets,
        audit_gates: request.audit_gates,
        bit_length: request.bit_length,
        argmin_arity: if request.argmin_arity == 0 {
            padded
        } else {
            request.argmin_arity
        },
        edabit: request.edabit,
        input_check: request.input_check,
        check_mode: CheckMode::PerParty,
        ..ProgramConfig::default()
    };
    let source = build_program(&config).map_err(|error| error.to_string())?;
    let policies = request
        .policies
        .as_ref()
        .map(|value| parse_policies(&value.to_string()).map_err(|error| error.to_string()))
        .transpose()?;
    if policies
        .as_ref()
        .is_some_and(|policies| policies.len() < request.n_mm)
    {
        return Err(format!("policies has fewer than {} entries", request.n_mm));
    }
    let input_config = InputConfig {
        n_mm: padded,
        n_real_mm: request.n_mm,
        n_parties: request.n_parties,
        is_real: request.is_real,
        n_requests: request.n_requests,
        n_assets: request.n_assets,
        ref_table: &ref_table,
        user_asset: request.user_asset,
        user_qty: request.user_qty,
        user_dir: request.user_dir,
        user_entity: 42,
        now_t: config.now_t,
        seed: request.seed,
        audit_gates: request.audit_gates,
        value_bits: request
            .bit_length
            .checked_add(1)
            .ok_or_else(|| "value bit width overflow".to_string())?,
        field_bits: 128,
        use_ref: 1,
        reference: config.reference,
        input_check: config.input_check,
        check_mode: config.check_mode,
        binding_limit: config.binding_limit,
        user_limit: 100_000,
        user_limit_blinding: 1,
        user_qty_blinding: 1,
        response_mask: None,
        fill_mask: None,
        check_coefficients: &config.check_coefficients,
        check_repeats: config.check_repeats,
        policies: policies.as_deref(),
        shamir_inputs: false,
        shamir_threshold: request.n_parties.saturating_sub(1) / 2,
        dvp: None,
        quote_proof: None,
    };
    let mut generated = build_inputs(&input_config).map_err(|error| error.to_string())?;
    finish_reference(&mut generated, &input_config, sentinel, request.mode)
        .map_err(|error| error.to_string())?;
    let reference =
        serde_json::from_str(&generated.reference_json()).map_err(|error| error.to_string())?;
    Ok(Generated {
        source,
        inputs: generated.party_files(),
        reference,
    })
}

/// Serve one JSON request and response per line. Each accepted connection is
/// handled independently; quotes themselves are serialized because MP-SPDZ's
/// `Player-Data` inputs are checkout-global files.
pub fn serve(cache: CircuitCache, host: &str, port: u16) -> QuoteResult<()> {
    let listener = TcpListener::bind((host, port)).map_err(|error| error.to_string())?;
    println!("serving on {host}:{port}");
    std::io::stdout()
        .flush()
        .map_err(|error| error.to_string())?;
    let cache = Arc::new(Mutex::new(cache));
    for stream in listener.incoming() {
        let stream = stream.map_err(|error| error.to_string())?;
        let cache = Arc::clone(&cache);
        thread::spawn(move || {
            let _ = handle_client(stream, &cache);
        });
    }
    Ok(())
}

fn handle_client(stream: TcpStream, cache: &Arc<Mutex<CircuitCache>>) -> QuoteResult<()> {
    let reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);
    let mut writer = BufWriter::new(stream);
    for line in reader.lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(line.trim()) {
            Ok(request) => {
                let started = Instant::now();
                match cache
                    .lock()
                    .map_err(|_| "circuit cache lock is poisoned".to_string())?
                    .quote(&request)
                {
                    Ok(result) => {
                        let mut value =
                            serde_json::to_value(result).map_err(|error| error.to_string())?;
                        let object = value
                            .as_object_mut()
                            .ok_or_else(|| "quote response is not an object".to_string())?;
                        let mut reply = Map::new();
                        reply.insert("ok".into(), Value::Bool(true));
                        reply.insert(
                            "service_ms".into(),
                            json!(started.elapsed().as_secs_f64() * 1_000.0),
                        );
                        reply.extend(object.clone());
                        Value::Object(reply)
                    }
                    Err(error) => json!({"ok": false, "error": format!("RuntimeError: {error}")}),
                }
            }
            Err(error) => json!({"ok": false, "error": format!("JSONDecodeError: {error}")}),
        };
        serde_json::to_writer(&mut writer, &reply).map_err(|error| error.to_string())?;
        writer.write_all(b"\n").map_err(|error| error.to_string())?;
        writer.flush().map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn start_proxy(run_dir: &Path, delay_ms: f64, proxies: &[Value]) -> QuoteResult<Child> {
    let config = run_dir.join("proxy.json");
    let ready = run_dir.join("proxy-ready.json");
    let _ = fs::remove_file(&ready);
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "one_way_delay_ms": delay_ms,
            "proxies": proxies,
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let executable = std::env::var_os("QOMM_WAN_PROXY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap_or_else(|_| PathBuf::from("wan_proxy"))
                .with_file_name("wan_proxy")
        });
    if !executable.is_file() {
        return Err(format!(
            "{} is missing; build qomm-transport --bin wan_proxy for delayed runs",
            executable.display()
        ));
    }
    let mut child = Command::new(executable)
        .args([
            "--config",
            config.to_str().ok_or("proxy config path is not UTF-8")?,
        ])
        .args([
            "--ready",
            ready.to_str().ok_or("proxy ready path is not UTF-8")?,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready.exists() && Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("wan_proxy exited before becoming ready".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    if !ready.exists() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("wan_proxy did not become ready".into());
    }
    Ok(child)
}

fn wait_all(children: &mut [Child], timeout: Duration) -> QuoteResult<bool> {
    let deadline = Instant::now() + timeout;
    let mut done = vec![false; children.len()];
    let mut ok = true;
    loop {
        let mut remaining = 0;
        for (party, child) in children.iter_mut().enumerate() {
            if done[party] {
                continue;
            }
            match child.try_wait().map_err(|error| error.to_string())? {
                Some(status) => {
                    done[party] = true;
                    ok &= status.success();
                }
                None => remaining += 1,
            }
        }
        if remaining == 0 {
            return Ok(ok);
        }
        if Instant::now() >= deadline {
            for child in children.iter_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn verify(mode: Mode, log: &str, reference: &Value) -> QuoteResult<(bool, String)> {
    let padded = integer(reference, "padded_mm")?;
    let mask = reference.get("mask").and_then(json_i128).unwrap_or(0);
    match mode {
        Mode::Rfq => {
            let Some(masked) = named_integer(log, "QOMM_MASKED_KEY=") else {
                return Ok((false, "no masked quote in log".into()));
            };
            let got = unpack_key(masked - mask, padded);
            let want = (
                integer(reference, "best_cost")?,
                integer(reference, "best_mm")?,
            );
            Ok((
                got == want,
                format!("got=({}, {}) want=({}, {})", got.0, got.1, want.0, want.1),
            ))
        }
        Mode::Rfm => {
            let (Some(ask), Some(bid)) = (
                named_integer(log, "QOMM_MASKED_ASK="),
                named_integer(log, "QOMM_MASKED_BID="),
            ) else {
                return Ok((false, "no two-sided quote in log".into()));
            };
            let got = (
                unpack_key(ask - mask, padded),
                unpack_key(bid - mask, padded),
            );
            let want = (
                (
                    integer(reference, "best_ask")?,
                    integer(reference, "best_ask_mm")?,
                ),
                (
                    -integer(reference, "best_bid")?,
                    integer(reference, "best_bid_mm")?,
                ),
            );
            Ok((
                got == want,
                format!(
                    "got=(({}, {}), ({}, {})) want=(({}, {}), ({}, {}))",
                    got.0 .0,
                    got.0 .1,
                    got.1 .0,
                    got.1 .1,
                    want.0 .0,
                    want.0 .1,
                    want.1 .0,
                    want.1 .1
                ),
            ))
        }
        Mode::Rfs => {
            let mut steps = Vec::new();
            for line in log.lines() {
                if let Some(rest) = line.strip_prefix("QOMM_RFS_STEP_") {
                    if let Some((index, key)) = rest.split_once("_KEY=") {
                        if let (Ok(index), Ok(key)) = (index.parse::<usize>(), key.parse::<i128>())
                        {
                            steps.push((index, key));
                        }
                    }
                }
            }
            steps.sort_by_key(|row| row.0);
            let Some((_, key)) = steps.first() else {
                return Ok((false, "no RFS price series in log".into()));
            };
            let first = unpack_key(*key, padded);
            let want = (
                integer(reference, "best_cost")?,
                integer(reference, "best_mm")?,
            );
            Ok((
                first == want,
                format!(
                    "steps={} first=({}, {}) want=({}, {})",
                    steps.len(),
                    first.0,
                    first.1,
                    want.0,
                    want.1
                ),
            ))
        }
    }
}

fn parse_seconds(text: &str) -> Option<f64> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("Time")?.trim_start();
        let rest = rest.strip_prefix('=')?.trim_start();
        rest.split_whitespace().next()?.parse().ok()
    })
}

fn parse_data_sent(text: &str) -> Option<(Option<f64>, Option<u64>)> {
    text.lines().find_map(|line| {
        let at = line.find("Data sent")?;
        if line[..at].contains("Global") {
            return None;
        }
        let rest = line[at + "Data sent".len()..].trim_start();
        let rest = rest.strip_prefix('=')?.trim_start();
        let mut fields = rest.split_whitespace();
        let mb = fields.next()?.parse().ok();
        let _mb_word = fields.next()?;
        let _in_word = fields.next()?;
        let rounds = fields
            .next()?
            .trim_start_matches('~')
            .replace(',', "")
            .parse()
            .ok();
        Some((mb, rounds))
    })
}

fn named_integer(log: &str, prefix: &str) -> Option<i128> {
    log.lines()
        .find_map(|line| line.strip_prefix(prefix)?.trim().parse().ok())
}

fn integer(value: &Value, key: &str) -> QuoteResult<i128> {
    value
        .get(key)
        .and_then(json_i128)
        .ok_or_else(|| format!("reference has no integer {key}"))
}

fn json_i128(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn unpack_key(key: i128, padded: i128) -> (i128, i128) {
    let index = key.rem_euclid(padded);
    ((key - index) / padded, index)
}

fn free_port_block(count: usize, start: u16) -> u16 {
    let mut base = start;
    while (base as usize) < 60_000usize.saturating_sub(count) {
        let listeners = (0..count)
            .map(|offset| TcpListener::bind(("127.0.0.1", base + offset as u16)))
            .collect::<Result<Vec<_>, _>>();
        if listeners.is_ok() {
            return base;
        }
        base = base.saturating_add(200);
    }
    panic!("no free port block after scan");
}

fn remove_matching(directory: &Path, prefix: &str, suffix: &str) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && name.ends_with(suffix) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn tail(text: &str, count: usize) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    chars[chars.len().saturating_sub(count)..].iter().collect()
}

fn string(object: &Map<String, Value>, key: &str, default: &str) -> QuoteResult<String> {
    object.get(key).map_or_else(
        || Ok(default.to_string()),
        |value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| format!("{key} must be a string"))
        },
    )
}

fn required_string(object: &Map<String, Value>, key: &str) -> QuoteResult<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn usize_field(object: &Map<String, Value>, key: &str, default: usize) -> QuoteResult<usize> {
    object.get(key).map_or(Ok(default), |value| {
        value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| format!("{key} must be a non-negative integer"))
    })
}

fn u32_field(object: &Map<String, Value>, key: &str, default: u32) -> QuoteResult<u32> {
    object.get(key).map_or(Ok(default), |value| {
        value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| format!("{key} must be a non-negative 32-bit integer"))
    })
}

fn i128_field(object: &Map<String, Value>, key: &str, default: i128) -> QuoteResult<i128> {
    object.get(key).map_or(Ok(default), |value| {
        json_i128(value).ok_or_else(|| format!("{key} must be an integer"))
    })
}

fn f64_field(object: &Map<String, Value>, key: &str, default: f64) -> QuoteResult<f64> {
    object.get(key).map_or(Ok(default), |value| {
        value
            .as_f64()
            .filter(|value| value.is_finite())
            .ok_or_else(|| format!("{key} must be a finite number"))
    })
}

fn bool_field(object: &Map<String, Value>, key: &str, default: bool) -> QuoteResult<bool> {
    object.get(key).map_or(Ok(default), |value| {
        value
            .as_bool()
            .ok_or_else(|| format!("{key} must be a boolean"))
    })
}

fn optional_i128_array(value: Option<&Value>) -> QuoteResult<Option<Vec<i128>>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let array = value
        .as_array()
        .ok_or_else(|| "ref_table must be an array or null".to_string())?;
    array
        .iter()
        .map(|value| json_i128(value).ok_or_else(|| "ref_table values must be integers".into()))
        .collect::<QuoteResult<Vec<_>>>()
        .map(Some)
}

pub fn load_approvals(path: &Path) -> QuoteResult<Vec<Approval>> {
    let value: Value = serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    value
        .as_array()
        .ok_or_else(|| "approved file must contain a JSON array".to_string())?
        .iter()
        .map(Approval::from_json)
        .collect()
}

pub fn write_approvals(path: &Path, entries: &[Value]) -> QuoteResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut bytes = serde_json::to_vec_pretty(entries).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_read_program_config_for_shape_fields() {
        let request = Request::from_value(&json!({})).unwrap();
        let defaults = ProgramConfig::default();
        assert_eq!(request.n_mm, defaults.n_mm);
        assert_eq!(request.n_parties, defaults.n_parties);
        assert_eq!(request.rfs_steps, defaults.rfs_steps);
        assert_eq!(request.argmin_arity, defaults.argmin_arity);
        assert_eq!(request.n_assets, defaults.n_assets);
        assert_eq!(request.n_requests, defaults.n_requests);
        assert!(request.input_check);
        assert!(request
            .shape()
            .as_array()
            .is_some_and(|pairs| pairs.iter().any(|pair| {
                pair.as_array().is_some_and(|pair| {
                    pair.first() == Some(&json!("input_check")) && pair.get(1) == Some(&json!(true))
                })
            })));
    }

    #[test]
    fn resident_service_refuses_unchecked_inputs() {
        let error = Request::from_value(&json!({"input_check": false})).unwrap_err();
        assert!(error.contains("refuses unchecked MPC inputs"), "{error}");
    }

    #[test]
    fn shape_excludes_input_only_fields() {
        let a = Request::from_value(&json!({"user_qty": 100, "seed": 7})).unwrap();
        let b = Request::from_value(&json!({"user_qty": 999, "seed": 9})).unwrap();
        assert_eq!(a.shape(), b.shape());
    }

    /// The file `--approve-into` writes has to be the file `--approved` reads.
    ///
    /// Shapes are arrays of `(name, value)` pairs. The loader keeps them as a
    /// `Value` and compares by equality rather than turning nested arrays into
    /// hash keys, so an approved file always loads back into the same shape.
    #[test]
    fn an_approved_file_loads_back_the_shape_it_was_written_from() {
        let request = Request::from_value(&json!({"n_mm": 1, "n_parties": 3, "threshold": 1}))
            .expect("request");
        let shape = request.shape();
        assert!(
            shape.as_array().is_some_and(|pairs| pairs
                .iter()
                .all(|pair| pair.as_array().is_some_and(|pair| pair.len() == 2))),
            "the on-disk shape is an array of pairs: {shape}"
        );

        let dir =
            std::env::temp_dir().join(format!("qomm-approval-round-trip-{}", std::process::id()));
        let path = dir.join("approved.json");
        let entries = vec![json!({
            "name": "shape0",
            "program_digest": "deadbeef",
            "shape": shape.clone(),
        })];
        write_approvals(&path, &entries).expect("write");
        let loaded = load_approvals(&path).expect("load");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].shape, shape);
        assert_eq!(loaded[0].name, "shape0");
        assert_eq!(loaded[0].program_digest, "deadbeef");
    }
}
