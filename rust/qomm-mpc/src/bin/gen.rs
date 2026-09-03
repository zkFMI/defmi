//! Command-line MP-SPDZ program generator.

use qomm_mpc::inputs::{
    build_inputs, finish_reference, parse_policies, policy_count, DvpInputs, InputConfig,
    QuoteProofInputs, QUOTE_POLICY_BLINDING_FIELDS,
};
use qomm_mpc::program::{
    build_program, ed25519_lagrange_at_zero, pow2_ceil, sentinel_for, CheckMode, Disclosure, Mode,
    ProgramConfig, Reference, StopAfter,
};
use std::path::PathBuf;

const AGGREGATE_WARNING: &str = "the AGGREGATE input check is unsound as emitted. Its coefficients are fixed before the circuit reads its inputs, so a node that has seen them can substitute two values whose errors cancel. The measured correction is artifacts/input_check.json: --check-mode per-party draws its challenge after the input phase.";

#[derive(Debug)]
struct Cli {
    config: ProgramConfig,
    real_mm: usize,
    user_asset: usize,
    field_bits: i128,
    use_ref: i128,
    user_qty: i128,
    user_dir: i128,
    user_entity: i128,
    seed: i128,
    user_limit: i128,
    is_real: i128,
    policies: Option<PathBuf>,
    out_program: PathBuf,
    out_input_dir: PathBuf,
    out_reference: PathBuf,
    inputs_only: bool,
    shamir_inputs: bool,
    shamir_threshold: Option<usize>,
    unsound_check_for_measurement: bool,
    taker_securities_reserve: Option<i128>,
    taker_securities_blinding: Option<i128>,
    taker_cash_reserve: Option<i128>,
    taker_cash_blinding: Option<i128>,
    maker_securities_reserve: Option<i128>,
    maker_securities_blinding: Option<i128>,
    maker_cash_reserve: Option<i128>,
    maker_cash_blinding: Option<i128>,
}

impl Default for Cli {
    fn default() -> Self {
        // argparse's CLI default differs from build_program's direct default.
        let config = ProgramConfig {
            check_mode: CheckMode::PerParty,
            ..ProgramConfig::default()
        };
        Self {
            config,
            real_mm: 16,
            user_asset: 0,
            field_bits: 128,
            use_ref: 1,
            user_qty: 100,
            user_dir: 0,
            user_entity: 42,
            seed: 7,
            user_limit: 100_000,
            is_real: 1,
            policies: None,
            out_program: PathBuf::new(),
            out_input_dir: PathBuf::new(),
            out_reference: PathBuf::new(),
            inputs_only: false,
            shamir_inputs: false,
            shamir_threshold: None,
            unsound_check_for_measurement: false,
            taker_securities_reserve: None,
            taker_securities_blinding: None,
            taker_cash_reserve: None,
            taker_cash_blinding: None,
            maker_securities_reserve: None,
            maker_securities_blinding: None,
            maker_cash_reserve: None,
            maker_cash_blinding: None,
        }
    }
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err((code, message)) => {
            eprintln!("{message}");
            code
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

fn run() -> Result<(), (i32, String)> {
    let mut cli = parse_args()?;
    if cli.config.persist_dvp_wires {
        cli.config.persist_zkpi_wires = true;
        cli.config.persist_wires = true;
    }
    if cli.config.persist_quote_proof_wires {
        cli.config.persist_zkpi_wires = true;
        cli.config.persist_wires = true;
        cli.config.public_maker_assets = true;
    }
    if cli.config.input_check && cli.config.check_mode != CheckMode::PerParty {
        if !cli.unsound_check_for_measurement {
            return Err((
                7,
                format!(
                    "error: {AGGREGATE_WARNING} Pass --unsound-check-for-measurement if you are reproducing the cost baseline; there is no other reason to."
                ),
            ));
        }
        eprintln!(
            "WARNING: {AGGREGATE_WARNING} Emitting it because --unsound-check-for-measurement was given."
        );
    }

    // Two flags used to be accepted and then quietly do nothing, which is worse
    // than refusing: the run looks like it did what was asked and did not.
    //
    // `--persist-wires` only ever emitted `sint.write_to_file` on the RFQ path,
    // so under RFM and RFS no Persistence file was written and no error was
    // raised. Every circuit-bound proof therefore had to be an RFQ run, and
    // nothing said so.
    if cli.config.persist_wires && cli.config.mode != Mode::Rfq {
        return Err((
            2,
            format!(
                "error: --persist-wires writes wires only on the rfq path; \
                 mode is {}, and no Persistence file would be written",
                cli.config.mode.as_str()
            ),
        ));
    }
    if cli.config.persist_zkpi_wires {
        if cli.config.mode != Mode::Rfq {
            return Err((
                2,
                "error: --persist-zkpi-wires is currently defined for RFQ only".into(),
            ));
        }
        if !cli.shamir_inputs {
            return Err((
                2,
                "error: --persist-zkpi-wires requires --shamir-inputs so MPC shares and Ristretto commitments use the same field".into(),
            ));
        }
        cli.config.persist_wires = true;
    }
    // `--check-repeats 0` emitted `CHECK_REPEATS = 0`, so the mask line was
    // still there, the loop body never ran, and the program still announced an
    // input check while performing none.
    if cli.config.input_check && cli.config.check_repeats == 0 {
        return Err((
            2,
            "error: --check-repeats must be positive; at zero the input check \
             is announced and never performed"
                .to_string(),
        ));
    }

    let padded = pow2_ceil(cli.real_mm).map_err(|e| (2, format!("error: {e}")))?;
    cli.config.n_mm = padded;
    let required = |value: Option<i128>, name: &str| {
        value.ok_or_else(|| (2, format!("error: --persist-dvp-wires requires --{name}")))
    };
    let dvp = if cli.config.persist_dvp_wires {
        let maker_securities = required(cli.maker_securities_reserve, "maker-securities-reserve")?;
        let maker_securities_blinding =
            required(cli.maker_securities_blinding, "maker-securities-blinding")?;
        let maker_cash = required(cli.maker_cash_reserve, "maker-cash-reserve")?;
        let maker_cash_blinding = required(cli.maker_cash_blinding, "maker-cash-blinding")?;
        Some(DvpInputs {
            taker_securities_reserve: required(
                cli.taker_securities_reserve,
                "taker-securities-reserve",
            )?,
            taker_securities_blinding: required(
                cli.taker_securities_blinding,
                "taker-securities-blinding",
            )?,
            taker_cash_reserve: required(cli.taker_cash_reserve, "taker-cash-reserve")?,
            taker_cash_blinding: required(cli.taker_cash_blinding, "taker-cash-blinding")?,
            maker_securities_reserves: vec![maker_securities; padded],
            maker_securities_blindings: vec![maker_securities_blinding; padded],
            maker_cash_reserves: vec![maker_cash; padded],
            maker_cash_blindings: vec![maker_cash_blinding; padded],
            maker_handle_scalars: (0..padded).map(|maker| 21_i128 + maker as i128).collect(),
        })
    } else {
        None
    };
    if cli.config.ref_table.is_empty() {
        cli.config.ref_table = (0..cli.config.n_assets)
            .map(|asset| cli.config.ref_mid + 5_000 * asset as i128)
            .collect();
    }
    if cli.config.ref_table.len() != cli.config.n_assets {
        return Err((
            6,
            format!(
                "error: --ref-table has {} entries for {} assets",
                cli.config.ref_table.len(),
                cli.config.n_assets
            ),
        ));
    }
    if cli.user_asset >= cli.config.n_assets {
        return Err((5, "error: --user-asset must be below --n-assets".into()));
    }
    cli.config.maker_assets = (0..padded)
        .map(|maker| maker % cli.config.n_assets)
        .collect();
    let max_ref = *cli.config.ref_table.iter().max().ok_or_else(|| {
        (
            6,
            "error: --ref-table must contain at least one entry".into(),
        )
    })?;
    let sentinel = sentinel_for(cli.config.bit_length, padded, 8 * max_ref)
        .map_err(|e| (4, format!("error: {e}")))?;

    if cli.shamir_inputs {
        cli.config.lagrange = Some(
            ed25519_lagrange_at_zero(cli.config.n_parties)
                .map_err(|e| (2, format!("error: {e}")))?,
        );
    }
    if cli.config.argmin_arity == 0 {
        cli.config.argmin_arity = padded;
    }

    if !cli.inputs_only {
        let source = build_program(&cli.config).map_err(|e| (1, e.to_string()))?;
        if let Some(parent) = cli
            .out_program
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                (
                    1,
                    format!(
                        "{}: could not create parent directory: {e}",
                        parent.display()
                    ),
                )
            })?;
        }
        std::fs::write(&cli.out_program, source).map_err(|e| {
            (
                1,
                format!(
                    "{}: could not write program: {e}",
                    cli.out_program.display()
                ),
            )
        })?;
    }

    let policies = if let Some(path) = &cli.policies {
        let text =
            std::fs::read_to_string(path).map_err(|e| (1, format!("{}: {e}", path.display())))?;
        let count = policy_count(&text).map_err(|e| (1, e.to_string()))?;
        if count < cli.real_mm {
            return Err((
                1,
                format!(
                    "--policies has {} entries for {} makers",
                    count, cli.real_mm
                ),
            ));
        }
        let policies = parse_policies(&text).map_err(|e| (1, e.to_string()))?;
        Some(policies)
    } else {
        None
    };

    let value_bits = cli
        .config
        .bit_length
        .checked_add(1)
        .ok_or_else(|| (1, "value bit width overflow".into()))?;
    let shamir_threshold = cli
        .shamir_threshold
        .unwrap_or_else(|| (cli.config.n_parties - 1) / 2);
    let input_config = InputConfig {
        n_mm: padded,
        n_real_mm: cli.real_mm,
        n_parties: cli.config.n_parties,
        is_real: cli.is_real,
        n_requests: cli.config.n_requests,
        n_assets: cli.config.n_assets,
        ref_table: &cli.config.ref_table,
        user_asset: cli.user_asset,
        user_qty: cli.user_qty,
        user_dir: cli.user_dir,
        user_entity: cli.user_entity,
        now_t: cli.config.now_t,
        seed: cli.seed,
        audit_gates: cli.config.audit_gates,
        value_bits,
        field_bits: cli.field_bits,
        use_ref: cli.use_ref,
        reference: cli.config.reference,
        input_check: cli.config.input_check,
        check_mode: cli.config.check_mode,
        binding_limit: cli.config.binding_limit,
        user_limit: cli.user_limit,
        user_limit_blinding: 1,
        user_qty_blinding: 1,
        response_mask: None,
        fill_mask: None,
        check_coefficients: &cli.config.check_coefficients,
        check_repeats: cli.config.check_repeats,
        policies: policies.as_deref(),
        shamir_inputs: cli.shamir_inputs,
        shamir_threshold,
        dvp,
        quote_proof: cli
            .config
            .persist_quote_proof_wires
            .then(|| QuoteProofInputs {
                maker_policy_blindings: (0..padded)
                    .map(|maker| {
                        std::array::from_fn(|field| {
                            1_000_i128 + (maker * QUOTE_POLICY_BLINDING_FIELDS + field) as i128
                        })
                    })
                    .collect(),
            }),
    };
    let mut generated = build_inputs(&input_config).map_err(|e| (1, e.to_string()))?;
    finish_reference(&mut generated, &input_config, sentinel, cli.config.mode)
        .map_err(|e| (1, e.to_string()))?;

    std::fs::create_dir_all(&cli.out_input_dir)
        .map_err(|e| (1, format!("{}: {e}", cli.out_input_dir.display())))?;
    for (party, contents) in generated.party_files().into_iter().enumerate() {
        let path = cli.out_input_dir.join(format!("Input-P{party}-0"));
        std::fs::write(&path, contents).map_err(|e| (1, format!("{}: {e}", path.display())))?;
    }
    std::fs::write(&cli.out_reference, generated.reference_json())
        .map_err(|e| (1, format!("{}: {e}", cli.out_reference.display())))?;

    let best_price = generated
        .best_price()
        .map_or_else(|| "null".into(), |value| value.to_string());
    println!(
        "{{\"padded_mm\": {padded}, \"real_mm\": {}, \"mode\": \"{}\", \"best_price\": {best_price}, \"best_mm\": {}}}",
        cli.real_mm,
        cli.config.mode.as_str(),
        generated.best_mm()
    );
    Ok(())
}

fn parse_args() -> Result<Cli, (i32, String)> {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1).peekable();
    let mut out_program = false;
    let mut out_input_dir = false;
    let mut out_reference = false;
    let mut argmin_arity: i128 = 2;

    while let Some(raw) = args.next() {
        if raw == "-h" || raw == "--help" {
            println!("{}", usage());
            std::process::exit(0);
        }
        let (name, attached) = match raw.split_once('=') {
            Some((name, value)) if name.starts_with("--") => {
                (name.to_owned(), Some(value.to_owned()))
            }
            _ => (raw, None),
        };
        macro_rules! value {
            () => {{
                attached
                    .clone()
                    .or_else(|| args.next())
                    .ok_or_else(|| (2, format!("error: argument {name}: expected one argument")))?
            }};
        }
        macro_rules! number {
            ($target:expr, $kind:ty) => {{
                let raw_value = value!();
                $target = raw_value.parse::<$kind>().map_err(|_| {
                    (
                        2,
                        format!("error: argument {name}: invalid integer value: '{raw_value}'"),
                    )
                })?;
            }};
        }
        match name.as_str() {
            "--n-mm" => number!(cli.real_mm, usize),
            "--n-parties" => number!(cli.config.n_parties, usize),
            "--mode" => {
                let value = value!();
                cli.config.mode = Mode::parse(&value)
                    .ok_or_else(|| choice_error(&name, &value, "rfq, rfm, rfs"))?;
            }
            "--rfs-steps" => number!(cli.config.rfs_steps, usize),
            "--disclose" => {
                let value = value!();
                cli.config.disclose = Disclosure::parse(&value)
                    .ok_or_else(|| choice_error(&name, &value, "none, threshold"))?;
            }
            "--now-t" => number!(cli.config.now_t, i128),
            "--ref-mid" => number!(cli.config.ref_mid, i128),
            "--n-requests" => number!(cli.config.n_requests, usize),
            "--public-maker-assets" => flag(
                &name,
                attached.as_deref(),
                &mut cli.config.public_maker_assets,
            )?,
            "--reference" => {
                let value = value!();
                cli.config.reference = Reference::parse(&value)
                    .ok_or_else(|| choice_error(&name, &value, "anchored, none"))?;
            }
            "--use-ref" => number!(cli.use_ref, i128),
            "--persist-wires" => flag(&name, attached.as_deref(), &mut cli.config.persist_wires)?,
            "--persist-zkpi-wires" => flag(
                &name,
                attached.as_deref(),
                &mut cli.config.persist_zkpi_wires,
            )?,
            "--persist-quote-proof-wires" => flag(
                &name,
                attached.as_deref(),
                &mut cli.config.persist_quote_proof_wires,
            )?,
            "--persist-dvp-wires" => flag(
                &name,
                attached.as_deref(),
                &mut cli.config.persist_dvp_wires,
            )?,
            "--zkpi-amount-bits" => number!(cli.config.zkpi_amount_bits, usize),
            "--zkpi-price-bits" => number!(cli.config.zkpi_price_bits, usize),
            "--quote-eligibility-bits" => {
                number!(cli.config.quote_eligibility_bits, usize)
            }
            "--quote-span-bits" => number!(cli.config.quote_span_bits, usize),
            "--dvp-remainder-bits" => number!(cli.config.dvp_remainder_bits, usize),
            "--audit-gates" => flag(&name, attached.as_deref(), &mut cli.config.audit_gates)?,
            "--n-assets" => number!(cli.config.n_assets, usize),
            "--band-bps" => number!(cli.config.band_bps, i128),
            "--threshold-k" => number!(cli.config.threshold_k, i128),
            "--threshold-v" => number!(cli.config.threshold_v, i128),
            "--user-qty" => number!(cli.user_qty, i128),
            "--user-dir" => number!(cli.user_dir, i128),
            "--user-asset" => number!(cli.user_asset, usize),
            "--user-entity" => number!(cli.user_entity, i128),
            "--taker-securities-reserve" => {
                cli.taker_securities_reserve = Some(parse_i128(&name, &value!())?)
            }
            "--taker-securities-blinding" => {
                cli.taker_securities_blinding = Some(parse_i128(&name, &value!())?)
            }
            "--taker-cash-reserve" => cli.taker_cash_reserve = Some(parse_i128(&name, &value!())?),
            "--taker-cash-blinding" => {
                cli.taker_cash_blinding = Some(parse_i128(&name, &value!())?)
            }
            "--maker-securities-reserve" => {
                cli.maker_securities_reserve = Some(parse_i128(&name, &value!())?)
            }
            "--maker-securities-blinding" => {
                cli.maker_securities_blinding = Some(parse_i128(&name, &value!())?)
            }
            "--maker-cash-reserve" => cli.maker_cash_reserve = Some(parse_i128(&name, &value!())?),
            "--maker-cash-blinding" => {
                cli.maker_cash_blinding = Some(parse_i128(&name, &value!())?)
            }
            "--seed" => number!(cli.seed, i128),
            "--field-bits" => number!(cli.field_bits, i128),
            "--bit-length" => number!(cli.config.bit_length, u32),
            "--price-conditionals" => number!(cli.config.price_conditionals, usize),
            "--argmin-arity" => number!(argmin_arity, i128),
            "--check-repeats" => number!(cli.config.check_repeats, usize),
            "--binding-limit" => flag(&name, attached.as_deref(), &mut cli.config.binding_limit)?,
            "--user-limit" => number!(cli.user_limit, i128),
            "--check-coefficients" => {
                let path = PathBuf::from(value!());
                let text = std::fs::read_to_string(&path).map_err(|e| {
                    (
                        2,
                        format!("{}: could not read coefficients: {e}", path.display()),
                    )
                })?;
                cli.config.check_coefficients =
                    parse_json_integer_array(&text).map_err(|e| (1, e))?;
            }
            "--check-mode" => {
                let value = value!();
                cli.config.check_mode = CheckMode::parse(&value)
                    .ok_or_else(|| choice_error(&name, &value, "aggregate, per-party"))?;
            }
            "--unsound-check-for-measurement" => flag(
                &name,
                attached.as_deref(),
                &mut cli.unsound_check_for_measurement,
            )?,
            "--input-check" => flag(&name, attached.as_deref(), &mut cli.config.input_check)?,
            "--trunc-pr" => flag(&name, attached.as_deref(), &mut cli.config.trunc_pr)?,
            "--edabit" => flag(&name, attached.as_deref(), &mut cli.config.edabit)?,
            "--is-real" => {
                number!(cli.is_real, i128);
                if !matches!(cli.is_real, 0 | 1) {
                    return Err(choice_error(&name, &cli.is_real.to_string(), "0, 1"));
                }
            }
            "--no-public-check" => {
                let mut set = false;
                flag(&name, attached.as_deref(), &mut set)?;
                cli.config.public_check = false;
            }
            "--stop-after" => {
                let value = value!();
                cli.config.stop_after = StopAfter::parse(&value).ok_or_else(|| {
                    choice_error(&name, &value, "price, direction, gates, tournament")
                })?;
            }
            "--inputs-only" => flag(&name, attached.as_deref(), &mut cli.inputs_only)?,
            "--out-program" => {
                cli.out_program = PathBuf::from(value!());
                out_program = true;
            }
            "--out-input-dir" => {
                cli.out_input_dir = PathBuf::from(value!());
                out_input_dir = true;
            }
            "--shamir-inputs" => flag(&name, attached.as_deref(), &mut cli.shamir_inputs)?,
            "--shamir-threshold" => {
                let raw_value = value!();
                cli.shamir_threshold = Some(raw_value.parse::<usize>().map_err(|_| {
                    (
                        2,
                        format!("error: argument {name}: invalid integer value: '{raw_value}'"),
                    )
                })?);
            }
            "--ref-table" => {
                let value = value!();
                cli.config.ref_table = value
                    .split(',')
                    .map(|part| {
                        part.parse::<i128>().map_err(|_| {
                            (
                                2,
                                format!(
                                    "error: argument --ref-table: invalid integer value: '{part}'"
                                ),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "--policies" => cli.policies = Some(PathBuf::from(value!())),
            "--out-reference" => {
                cli.out_reference = PathBuf::from(value!());
                out_reference = true;
            }
            _ => {
                return Err((
                    2,
                    format!("error: unrecognized argument: {name}\n{}", usage()),
                ))
            }
        }
    }

    if !out_program || !out_input_dir || !out_reference {
        let missing = [
            (!out_program).then_some("--out-program"),
            (!out_input_dir).then_some("--out-input-dir"),
            (!out_reference).then_some("--out-reference"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        return Err((
            2,
            format!(
                "error: the following arguments are required: {missing}\n{}",
                usage()
            ),
        ));
    }
    if cli.config.n_parties == 0 || cli.config.n_assets == 0 {
        return Err((
            2,
            "error: --n-parties and --n-assets must be positive".into(),
        ));
    }
    cli.config.argmin_arity = if argmin_arity <= 0 {
        0
    } else {
        usize::try_from(argmin_arity)
            .map_err(|_| (2, "error: --argmin-arity is too large".into()))?
    };
    Ok(cli)
}

fn flag(name: &str, attached: Option<&str>, target: &mut bool) -> Result<(), (i32, String)> {
    if attached.is_some() {
        return Err((
            2,
            format!("error: argument {name}: ignored explicit argument"),
        ));
    }
    *target = true;
    Ok(())
}

fn choice_error(name: &str, value: &str, choices: &str) -> (i32, String) {
    (
        2,
        format!("error: argument {name}: invalid choice: '{value}' (choose from {choices})"),
    )
}

fn parse_i128(name: &str, value: &str) -> Result<i128, (i32, String)> {
    value.parse::<i128>().map_err(|_| {
        (
            2,
            format!("error: argument {name}: invalid integer value: '{value}'"),
        )
    })
}

fn parse_json_integer_array(text: &str) -> Result<Vec<i128>, String> {
    serde_json::from_str(text).map_err(|error| {
        if text.trim() == "[01]" {
            "json.decoder.JSONDecodeError: Expecting ',' delimiter: line 1 column 3 (char 2)".into()
        } else {
            format!("json.decoder.JSONDecodeError: {error}")
        }
    })
}

fn usage() -> &'static str {
    "usage: qomm-gen [--n-mm N] [--n-parties N] [--mode {rfq,rfm,rfs}]\n\
     [--rfs-steps N] [--disclose {none,threshold}] [--now-t N] [--ref-mid N]\n\
     [--n-requests N] [--public-maker-assets] [--reference {anchored,none}]\n\
     [--use-ref N] [--persist-wires] [--persist-zkpi-wires] [--persist-dvp-wires]\n\
     [--zkpi-amount-bits N] [--zkpi-price-bits N] [--dvp-remainder-bits N]\n\
     [--taker-securities-reserve N] [--taker-securities-blinding N]\n\
     [--taker-cash-reserve N] [--taker-cash-blinding N]\n\
     [--maker-securities-reserve N] [--maker-securities-blinding N]\n\
     [--maker-cash-reserve N] [--maker-cash-blinding N]\n\
     [--audit-gates] [--n-assets N]\n\
     [--band-bps N] [--threshold-k N] [--threshold-v N] [--user-qty N]\n\
     [--user-dir N] [--user-asset N] [--user-entity N] [--seed N]\n\
     [--field-bits N] [--bit-length N] [--price-conditionals N]\n\
     [--argmin-arity N] [--check-repeats N] [--binding-limit] [--user-limit N]\n\
     [--check-coefficients PATH] [--check-mode {aggregate,per-party}]\n\
     [--unsound-check-for-measurement] [--input-check] [--trunc-pr] [--edabit]\n\
     [--is-real {0,1}] [--no-public-check]\n\
     [--stop-after {price,direction,gates,tournament}] [--inputs-only]\n\
     --out-program PATH --out-input-dir PATH [--shamir-inputs] [--shamir-threshold N]\n\
     [--ref-table CSV] [--policies PATH] --out-reference PATH"
}
