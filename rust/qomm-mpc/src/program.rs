//! Deterministic MP-SPDZ source generation for the QOMM circuit.
//!
//! QOMM owns this generator and all orchestration in Rust. The generated text
//! uses MP-SPDZ's official compiler input language; only that upstream compiler
//! boundary is allowed to invoke its bundled interpreter.

use qomm_dsl::compile_rule;
use qomm_dsl::emit::to_mpc_with_bindings;
use qomm_dsl::registry::{rule_digest, POLICY_RULE_DIGEST_MARKER};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const FIELDS: [&str; 10] = [
    "asset",
    "ask_level",
    "spread",
    "slope",
    "invcoef",
    "inv",
    "maxqty",
    "expiry",
    "active",
    "use_ref",
];

/// Bit widths used by the production QOMM product circuit and by the public
/// zkPI/DvP proof coordinator. Keep these values in one crate so persisted MPC
/// witnesses can never be interpreted with a narrower verifier bound.
pub const PRODUCT_ZKPI_AMOUNT_BITS: usize = 64;
pub const PRODUCT_ZKPI_PRICE_BITS: usize = 32;
// DeFMI's settlement-verifier epoch publishes one amount bound and applies it
// both to the transferred quantity and to the two reservation remainders.
// The MPC persistence must therefore use that exact width: a different valid
// Bulletproof width would produce a proof that the public DeFMI verifier is
// required to reject even when the underlying remainder is non-negative.
pub const PRODUCT_DVP_REMAINDER_BITS: usize = PRODUCT_ZKPI_AMOUNT_BITS;
pub const PRODUCT_QUOTE_ELIGIBILITY_BITS: usize = 48;
pub const PRODUCT_QUOTE_SPAN_BITS: usize = 48;

const fn is_bulletproof_width(bits: usize) -> bool {
    matches!(bits, 8 | 16 | 32 | 64)
}

/// The scalar field order of Ed25519, used by the Shamir input option.
pub const ED25519_ORDER: &str =
    "7237005577332262213973186563042994240857116359379907606001950938285454250989";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Rfq,
    Rfm,
    Rfs,
}

impl Mode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rfq" => Some(Self::Rfq),
            "rfm" => Some(Self::Rfm),
            "rfs" => Some(Self::Rfs),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rfq => "rfq",
            Self::Rfm => "rfm",
            Self::Rfs => "rfs",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disclosure {
    None,
    Threshold,
}

impl Disclosure {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "threshold" => Some(Self::Threshold),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Threshold => "threshold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckMode {
    Aggregate,
    PerParty,
}

impl CheckMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "aggregate" => Some(Self::Aggregate),
            "per-party" => Some(Self::PerParty),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopAfter {
    Price,
    Direction,
    Gates,
    Tournament,
}

impl StopAfter {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "price" => Some(Self::Price),
            "direction" => Some(Self::Direction),
            "gates" => Some(Self::Gates),
            "tournament" => Some(Self::Tournament),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reference {
    Anchored,
    None,
}

impl Reference {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "anchored" => Some(Self::Anchored),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ProgramConfig {
    pub n_mm: usize,
    pub n_parties: usize,
    pub mode: Mode,
    pub rfs_steps: usize,
    pub disclose: Disclosure,
    pub now_t: i128,
    pub ref_mid: i128,
    pub band_bps: i128,
    pub threshold_k: i128,
    pub threshold_v: i128,
    pub public_check: bool,
    pub n_requests: usize,
    pub n_assets: usize,
    pub ref_table: Vec<i128>,
    pub maker_assets: Vec<usize>,
    pub public_maker_assets: bool,
    pub audit_gates: bool,
    pub bit_length: u32,
    pub argmin_arity: usize,
    pub lagrange: Option<Vec<String>>,
    pub price_conditionals: usize,
    pub edabit: bool,
    pub trunc_pr: bool,
    pub input_check: bool,
    pub check_mode: CheckMode,
    pub binding_limit: bool,
    pub challenge_bits: u32,
    pub check_coefficients: Vec<i128>,
    pub check_repeats: usize,
    pub stop_after: StopAfter,
    pub persist_wires: bool,
    /// Persist the amount/price blindings, bit decompositions, and product
    /// cross terms needed for a threshold zkPI. This is separate from the
    /// legacy circuit-wire fixture so old measurement artifacts keep their
    /// exact layout.
    pub persist_zkpi_wires: bool,
    /// Persist every node-local share required to prove the complete quote
    /// computation (registered policy, eligibility, winner and minimality),
    /// rather than only the amount/price payment instruction.
    pub persist_quote_proof_wires: bool,
    pub zkpi_amount_bits: usize,
    pub zkpi_price_bits: usize,
    pub quote_eligibility_bits: usize,
    pub quote_span_bits: usize,
    /// Persist the price/cash product and both reservation remainders needed
    /// for a threshold DvP proof.  This extends (and therefore requires) the
    /// threshold-zkPI handoff.
    pub persist_dvp_wires: bool,
    pub dvp_remainder_bits: usize,
    pub reference: Reference,
    pub range_query: bool,
    pub query_lo: i128,
    pub query_hi: i128,
}

impl Default for ProgramConfig {
    fn default() -> Self {
        let n_mm = 16;
        Self {
            n_mm,
            n_parties: 7,
            mode: Mode::Rfq,
            rfs_steps: 5,
            disclose: Disclosure::None,
            now_t: 1000,
            ref_mid: 100_000,
            band_bps: 20,
            threshold_k: 5,
            threshold_v: 1000,
            public_check: true,
            n_requests: 1,
            n_assets: 1,
            // Empty, so the binary's `--ref-table` default (ref_mid + 5000 * asset)
            // actually fires. A one-element default
            // is never empty, so that branch never ran and every run with more than
            // one asset was refused unless the table was passed by hand.
            ref_table: Vec::new(),
            maker_assets: vec![0; n_mm],
            public_maker_assets: false,
            audit_gates: false,
            bit_length: 63,
            argmin_arity: 2,
            lagrange: None,
            price_conditionals: 0,
            edabit: false,
            trunc_pr: false,
            input_check: false,
            check_mode: CheckMode::Aggregate,
            binding_limit: false,
            challenge_bits: 64,
            check_coefficients: Vec::new(),
            check_repeats: 7,
            stop_after: StopAfter::Tournament,
            persist_wires: false,
            persist_zkpi_wires: false,
            persist_quote_proof_wires: false,
            zkpi_amount_bits: 32,
            zkpi_price_bits: 32,
            quote_eligibility_bits: 34,
            quote_span_bits: 32,
            persist_dvp_wires: false,
            dvp_remainder_bits: 32,
            reference: Reference::Anchored,
            range_query: false,
            query_lo: 0,
            query_hi: 0,
        }
    }
}

pub const POLICY_RULE_NAME: &str = "qomm_quote_policy";

/// Canonical price-policy DSL used by the product MPC generator.
///
/// These are venue admission bounds, not fixture values.  The same checked AST
/// emits the executable assignments below and the rule digest accepted by the
/// circuit registry, so an operator can no longer pair one audited rule with a
/// different handwritten price formula.
pub fn policy_rule_source(config: &ProgramConfig) -> String {
    let mut skew = "invcoef * inv".to_string();
    for index in 0..config.price_conditionals {
        let bound = 200 * (index + 1);
        skew = if index % 2 == 0 {
            format!("max({skew}, -{bound})")
        } else {
            format!("min({skew}, {bound})")
        };
    }
    let (declarations, anchored) = match config.reference {
        Reference::Anchored => (
            concat!(
                "param ask_level[-200000,200000] spread[0,200000] slope[0,16] ",
                "invcoef[-8,8] use_ref[0,1]\n",
                "state inv[-4000,4000]\n",
                "input qty[1,1000] ref_price[0,1000000]\n"
            ),
            "ask_level + use_ref * ref_price",
        ),
        Reference::None => (
            concat!(
                "param ask_level[-200000,200000] spread[0,200000] slope[0,16] ",
                "invcoef[-8,8]\n",
                "state inv[-4000,4000]\n",
                "input qty[1,1000]\n"
            ),
            "ask_level",
        ),
    };
    format!(
        concat!(
            "{declarations}",
            "anchored = {anchored}\n",
            "depth = slope * qty\n",
            "skew = {skew}\n",
            "ask = ({anchored}) + slope * qty + ({skew})\n",
            "bid = ({anchored}) - spread - slope * qty + ({skew})\n"
        ),
        declarations = declarations,
        anchored = anchored,
        skew = skew,
    )
}

pub fn policy_rule_digest(config: &ProgramConfig) -> Result<String, ProgramError> {
    let rule = compile_rule(&policy_rule_source(config), POLICY_RULE_NAME)
        .map_err(|error| ProgramError(error.to_string()))?;
    Ok(rule_digest(&rule))
}

fn policy_assignments(config: &ProgramConfig) -> Result<(String, Vec<String>), ProgramError> {
    let rule = compile_rule(&policy_rule_source(config), POLICY_RULE_NAME)
        .map_err(|error| ProgramError(error.to_string()))?;
    let digest = rule_digest(&rule);
    let mut bindings = BTreeMap::from([
        ("ask_level".to_string(), "ask_level".to_string()),
        ("spread".to_string(), "spread".to_string()),
        ("slope".to_string(), "slope".to_string()),
        ("invcoef".to_string(), "invcoef".to_string()),
        ("inv".to_string(), "tile_makers(inv_vec)".to_string()),
        ("qty".to_string(), "qty_v".to_string()),
    ]);
    if config.reference == Reference::Anchored {
        bindings.insert("use_ref".into(), "use_ref".into());
        bindings.insert(
            "ref_price".into(),
            "spread_request(ref_secret_per_request)".into(),
        );
    }
    let emitted =
        to_mpc_with_bindings(&rule, &bindings).map_err(|error| ProgramError(error.to_string()))?;
    let assignments = ["anchored", "depth", "skew", "ask", "bid"]
        .into_iter()
        .map(|name| {
            emitted
                .get(name)
                .map(|expression| format!("{name} = {expression}"))
                .ok_or_else(|| ProgramError(format!("policy rule omitted output {name}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((digest, assignments))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramError(pub String);

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProgramError {}

pub fn pow2_ceil(n: usize) -> Result<usize, ProgramError> {
    if n == 0 {
        return Ok(1);
    }
    n.checked_next_power_of_two()
        .ok_or_else(|| ProgramError(format!("cannot pad {n} makers to a power of two")))
}

pub fn sentinel_for(
    bit_length: u32,
    padded_mm: usize,
    max_cost: i128,
) -> Result<i128, ProgramError> {
    if !(2..=127).contains(&bit_length) || padded_mm == 0 {
        return Err(ProgramError(format!(
            "bit_length={bit_length} cannot pack {padded_mm} makers"
        )));
    }
    let headroom = 1_i128 << (bit_length - 2);
    let sentinel = headroom / padded_mm as i128;
    if sentinel <= max_cost {
        let need = bit_length_i128(max_cost * padded_mm as i128 * 4) + 1;
        return Err(ProgramError(format!(
            "bit_length={bit_length} is too narrow: packing {padded_mm} makers with costs up to {max_cost} needs at least {need} bits"
        )));
    }
    Ok(sentinel)
}

fn bit_length_i128(value: i128) -> u32 {
    if value <= 0 {
        0
    } else {
        128 - value.leading_zeros()
    }
}

fn mp_spdz_bool(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}

fn mp_spdz_list<T: fmt::Display>(values: &[T]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn default_check_coefficients() -> Vec<i128> {
    (0..64).map(|k| 1 + (617 * k) % 63).collect()
}

/// Lagrange-at-zero coefficients for evaluation points `1..=parties` over the
/// Ed25519 scalar field. For consecutive points they are
/// `(-1)^(i-1) * binomial(parties, i)`, so only subtraction of a small integer
/// from the decimal modulus is required.
pub fn ed25519_lagrange_at_zero(parties: usize) -> Result<Vec<String>, ProgramError> {
    if parties == 0 {
        return Ok(Vec::new());
    }
    let mut choose = 1_u128;
    let mut out = Vec::with_capacity(parties);
    for i in 1..=parties {
        choose = choose
            .checked_mul((parties + 1 - i) as u128)
            .and_then(|v| v.checked_div(i as u128))
            .ok_or_else(|| {
                ProgramError("party count is too large for Lagrange coefficients".into())
            })?;
        if i % 2 == 1 {
            out.push(choose.to_string());
        } else {
            out.push(decimal_sub_u128(ED25519_ORDER, choose)?);
        }
    }
    Ok(out)
}

fn decimal_sub_u128(value: &str, rhs: u128) -> Result<String, ProgramError> {
    let mut digits = value.bytes().map(|b| b - b'0').collect::<Vec<_>>();
    let mut rhs_digits = rhs
        .to_string()
        .bytes()
        .rev()
        .map(|b| b - b'0')
        .collect::<Vec<_>>();
    rhs_digits.resize(digits.len(), 0);
    let mut borrow = 0_i16;
    for (offset, rhs_digit) in rhs_digits.into_iter().enumerate() {
        let index = digits.len() - 1 - offset;
        let mut digit = digits[index] as i16 - rhs_digit as i16 - borrow;
        if digit < 0 {
            digit += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        digits[index] = digit as u8;
    }
    if borrow != 0 {
        return Err(ProgramError(
            "Lagrange coefficient exceeds the field".into(),
        ));
    }
    let first = digits
        .iter()
        .position(|d| *d != 0)
        .unwrap_or(digits.len() - 1);
    Ok(digits[first..]
        .iter()
        .map(|d| char::from(b'0' + *d))
        .collect())
}

struct Lines(Vec<String>);

impl Lines {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, line: impl Into<String>) {
        self.0.push(line.into());
    }

    /// In a raw block every emitted line is marked with `|`. Rust indentation
    /// before that marker is discarded; everything after it is output exactly.
    fn block(&mut self, block: &str) {
        for line in block.lines() {
            if let Some(marker) = line.find('|') {
                self.push(&line[marker + 1..]);
            }
        }
    }

    fn finish(self) -> String {
        self.0.join("\n") + "\n"
    }
}

pub fn build_program(config: &ProgramConfig) -> Result<String, ProgramError> {
    let c = config;
    if c.persist_zkpi_wires && !c.persist_wires {
        return Err(ProgramError(
            "zkPI persistence requires the circuit wire persistence block".into(),
        ));
    }
    if c.persist_quote_proof_wires
        && (!c.persist_zkpi_wires
            || !c.public_maker_assets
            || c.n_requests != 1
            || c.quote_eligibility_bits == 0
            || c.quote_eligibility_bits > 64
            || c.quote_span_bits == 0
            || c.quote_span_bits > 64)
    {
        return Err(ProgramError(
            "full quote-proof persistence requires one request, zkPI persistence, public maker assets, and 1..=64 eligibility/minimality widths".into(),
        ));
    }
    if c.persist_zkpi_wires
        && (!is_bulletproof_width(c.zkpi_amount_bits) || !is_bulletproof_width(c.zkpi_price_bits))
    {
        return Err(ProgramError(
            "zkPI amount and price widths must be one of 8, 16, 32 or 64 bits".into(),
        ));
    }
    if c.persist_dvp_wires
        && (!c.persist_zkpi_wires || c.dvp_remainder_bits == 0 || c.dvp_remainder_bits > 64)
    {
        return Err(ProgramError(
            "DvP persistence requires zkPI persistence and a 1..=64 remainder width".into(),
        ));
    }
    if c.stop_after != StopAfter::Tournament && c.mode != Mode::Rfq {
        return Err(ProgramError(format!(
            "--stop-after names layers of the RFQ circuit; mode {} is built differently",
            c.mode.as_str()
        )));
    }
    let ref_table = if c.ref_table.is_empty() {
        vec![c.ref_mid]
    } else {
        c.ref_table.clone()
    };
    let check_coefficients = if c.check_coefficients.is_empty() {
        default_check_coefficients()
    } else {
        c.check_coefficients.clone()
    };
    let maker_assets = if c.maker_assets.is_empty() {
        (0..c.n_mm).map(|i| i % c.n_assets).collect::<Vec<_>>()
    } else {
        c.maker_assets.clone()
    };
    let max_ref = *ref_table
        .iter()
        .max()
        .ok_or_else(|| ProgramError("reference table is empty".into()))?;
    let large = sentinel_for(c.bit_length, c.n_mm, 8 * max_ref)?;
    let mut w = Lines::new();

    w.push("\"\"\"QOMM: query-oblivious quote evaluation (generated; do not edit).");
    w.push("");
    let mut description = format!(
        "mode={} M={} parties={} disclose={} bits={} argmin_arity={} edabit={} trunc_pr={} price_conditionals={}",
        c.mode.as_str(),
        c.n_mm,
        c.n_parties,
        c.disclose.as_str(),
        c.bit_length,
        c.argmin_arity,
        mp_spdz_bool(c.edabit),
        mp_spdz_bool(c.trunc_pr),
        c.price_conditionals
    );
    if c.mode == Mode::Rfs {
        description.push_str(&format!(" rfs_steps={}", c.rfs_steps));
    }
    w.push(description);
    w.push("\"\"\"");
    w.push("");
    w.push(format!("program.set_bit_length({})", c.bit_length));
    if c.edabit {
        w.push("# push comparison bit generation into preprocessing");
        w.push("program.use_edabit(True)");
    }
    if c.trunc_pr {
        w.block(
            r###"
            |# probabilistic truncation: the mask is value-width plus a statistical
            |# gap rather than a whole field element, which is the difference that
            |# a wide field makes to a comparison.
            |program.use_trunc_pr = True
            "###,
        );
    }
    w.push("");
    w.push(format!("M = {}", c.n_mm));
    w.push(format!("N_PARTIES = {}", c.n_parties));
    w.push(format!("LARGE = {large}"));
    if c.persist_quote_proof_wires {
        // A product quote circuit is compiled once and serves many epochs.
        // MP-SPDZ reads this public value from the round-local
        // Programs/Public-Input file at execution time. Keeping `now_t` as a
        // compile-time constant made the MPC freshness wire disagree with the
        // public quote proof as soon as the first live round used another
        // timestamp.
        w.push("from Compiler.library import public_input");
        w.push("NOW_T = public_input()");
    } else {
        w.push(format!("NOW_T = {}", c.now_t));
    }
    if c.persist_zkpi_wires {
        w.push(format!("ZKPI_AMOUNT_BITS = {}", c.zkpi_amount_bits));
        w.push(format!("ZKPI_PRICE_BITS = {}", c.zkpi_price_bits));
    }
    if c.persist_quote_proof_wires {
        w.push(format!(
            "QUOTE_ELIGIBILITY_BITS = {}",
            c.quote_eligibility_bits
        ));
        w.push(format!("QUOTE_SPAN_BITS = {}", c.quote_span_bits));
    }
    if c.persist_dvp_wires {
        w.push(format!("DVP_REMAINDER_BITS = {}", c.dvp_remainder_bits));
    }
    if c.range_query {
        w.push("# The asker's range. Public, because it is their own question.");
        w.push(format!("QUERY_LO = {}", c.query_lo));
        w.push(format!("QUERY_HI = {}", c.query_hi));
    }
    w.push(format!("N_ASSETS = {}", c.n_assets));
    w.block(
        r###"
        |# Public reference price per asset. The table is public; which entry the
        |# request selects is not, so the selection has to be oblivious.
        "###,
    );
    w.push(format!("REF_TABLE = {}", mp_spdz_list(&ref_table)));
    w.push(format!("MAKER_ASSET = {}", mp_spdz_list(&maker_assets)));
    w.push(format!(
        "REF_MID = {}   # only used for the sentinel scale",
        c.ref_mid
    ));
    w.push("");

    let checking = c.input_check && c.check_mode == CheckMode::PerParty;
    if checking {
        let n_checked_values = 4 * c.n_requests
            + 2
            + usize::from(c.binding_limit) * 4
            + usize::from(c.persist_dvp_wires) * (4 + 5 * c.n_mm)
            + c.n_mm * FIELDS.len()
            + usize::from(c.persist_quote_proof_wires) * 9 * c.n_mm;
        w.push(format!("CHALLENGE_BITS = {}", c.challenge_bits));
        w.block(
            r###"
            |# ---- the input check's challenge, and why it is where it is ------
            |# The coefficients have to be unpredictable at the moment a node
            |# fixes its input, and the input is fixed when this program reads
            |# it. An earlier version derived them from the dealer's
            |# commitments, which are published before that --- so a node that
            |# had seen them could feed x_1 + c_2*k and x_2 - c_1*k and the
            |# combination cancelled identically, every time, with no security
            |# parameter to raise.
            |#
            |# So the shares are kept as they are read, one random value is
            |# opened once every input is in, and the coefficients are its
            |# powers. Public times secret is local, so the combination still
            |# costs no communication; the price is that one opening.
            |#
            |# Taking the check modulo the MPC prime is what makes the bound
            |# clean: sum_k rho^k e_k + e_m = 0 is a degree-m polynomial in rho,
            |# so a fixed non-zero error survives with probability at most m/p.
            |# It also removes the width budget entirely --- nothing has to avoid
            |# reducing, because the statement is modulo p on both sides.
            "###,
        );
        w.push(format!("N_CHECKED = {n_checked_values}"));
        w.push("check_store = [Array(N_CHECKED, sint) for _ in range(N_PARTIES)]");
        w.push("check_pos = [0]");
        w.push("");
    }
    if let Some(lagrange) = &c.lagrange {
        w.push(format!("LAGRANGE = {}", mp_spdz_list(lagrange)));
    }

    w.push("def secret_input():");
    if checking {
        w.push("    _k = check_pos[0]");
    }
    w.block(
        r###"
        |    total = None
        |    for _p in range(N_PARTIES):
        |        _s = sint.get_input_from(_p)
        "###,
    );
    if checking {
        w.push("        check_store[_p][_k] = _s");
    }
    if c.lagrange.is_some() {
        w.push("        _s = LAGRANGE[_p] * _s");
    }
    w.push("        total = _s if total is None else total + _s");
    if checking {
        w.push("    check_pos[0] += 1");
    }
    w.block(
        r###"
        |    return total
        |
        |# ---- user request, shared by the trader across every node ----
        "###,
    );
    w.push(format!("N_REQ = {}", c.n_requests));
    w.block(
        r###"
        |req_asset = Array(N_REQ, sint)
        |req_qty = Array(N_REQ, sint)
        |req_dir = Array(N_REQ, sint)   # 0 = user buys (takes ask), 1 = user sells
        |req_entity = Array(N_REQ, sint)
        |for r in range(N_REQ):
        |    req_asset[r] = secret_input()
        |    req_qty[r] = secret_input()
        |    req_dir[r] = secret_input()
        |    req_entity[r] = secret_input()
        |u_asset = req_asset[0]
        |u_qty = req_qty[0]
        |u_dir = req_dir[0]
        |u_entity = req_entity[0]
        |# Every slot runs on the fixed schedule whether or not a real request
        |# arrived. The flag is secret and never branched on, so the circuit shape,
        |# the round count and the byte count are identical either way; it only
        |# stops a dummy slot from moving market-maker state.
        |u_is_real = secret_input()
        |
        |# The trader's one-time mask. The answer leaves the circuit as
        |# `best_key + mask` opened to everyone, which is uniform to everyone but
        |# the trader, who subtracts. `reveal_to(0)` handed the winning price and
        |# the winning maker to computing node 0 in the clear -- the one party
        |# that is not supposed to learn the answer to a request it cannot read.
        |u_mask = secret_input()
        "###,
    );
    if c.persist_dvp_wires {
        w.block(
            r###"
            |
            |# ---- pre-authorized DeFMI reservation openings -----------------
            |# These arrive as Shamir shares from the reserve-admission path.
            |# Their public commitments are checked when the distributed DvP
            |# proof statement is assembled; inconsistent openings cannot be
            |# converted into a proof for the on-ledger reservations.
            |# The Taker has only the direction-relevant reserve in normal use;
            |# the other pair is a sharing of zero.  Makers register both sides
            |# with their standing policy because the direction and winner stay
            |# secret until this circuit selects them.
            |dvp_taker_securities_reserve = secret_input()
            |dvp_taker_securities_blinding = secret_input()
            |dvp_taker_cash_reserve = secret_input()
            |dvp_taker_cash_blinding = secret_input()
            |dvp_maker_securities_reserves = Array(M, sint)
            |dvp_maker_securities_blindings = Array(M, sint)
            |dvp_maker_cash_reserves = Array(M, sint)
            |dvp_maker_cash_blindings = Array(M, sint)
            |dvp_maker_handle_scalars = Array(M, sint)
            |for _m in range(M):
            |    dvp_maker_securities_reserves[_m] = secret_input()
            |    dvp_maker_securities_blindings[_m] = secret_input()
            |    dvp_maker_cash_reserves[_m] = secret_input()
            |    dvp_maker_cash_blindings[_m] = secret_input()
            |    dvp_maker_handle_scalars[_m] = secret_input()
            "###,
        );
    }
    if c.binding_limit {
        w.block(
            r###"
            |
            |# ---- the taker's acceptance level, committed with the request ----
            |# Today a quote is an offer: the taker reads it and decides. That is
            |# what makes probing free --- ask, read, walk away, repeat. A
            |# committed level turns the offer into an order: a quote at or inside
            |# it IS a trade, so the only way to learn the market is better than
            |# some level is to trade at it.
            |#
            |# What stays free is the other direction. A taker can raise the level
            |# from below and learn `worse than this` each time at no cost, exactly
            |# as an unfilled limit order in a public book tells you the market is
            |# worse than where you posted. So this does not stop probing; it puts
            |# the leak at the same place a central limit order book already has
            |# it, and no further --- and `L` is committed rather than displayed,
            |# so it is one step better than the book.
            |u_limit = secret_input()
            |# This opening is supplied as a ninth fixed-frame field. It never
            |# leaves MPC; its only output is the joint proof that the selected
            |# quote is on the executable side of the signed commitment.
            |u_limit_blinding = secret_input()
            |fill_mask = secret_input()
            |# Signed before submission and reused by the threshold zkPI.  A
            |# post-quote random blinding would create a different quantity
            |# commitment from the one in the Taker's execution mandate.
            |u_qty_blinding = secret_input()
            "###,
        );
    } else if c.persist_zkpi_wires {
        // Legacy non-auto-settlement circuits do not carry a signed Taker
        // mandate. Preserve their input layout while keeping the shared zkPI
        // persistence block well-formed.
        w.push("u_qty_blinding = sint.get_random()");
    }
    w.block(
        r###"
        |
        |# ---- market-maker price policies, one column per field ----
        "###,
    );
    for field in FIELDS {
        w.push(format!("col_{field} = Array(M, sint)"));
    }
    w.block(
        r###"
        |
        |# Each maker deals its own policy to every node. The previous form gave
        |# maker i entirely to node i % N_PARTIES, which is a policy in the clear
        |# at one of the nodes it is supposed to be hidden from.
        |for i in range(M):
        "###,
    );
    for field in FIELDS {
        w.push(format!("    col_{field}[i] = secret_input()"));
    }
    w.push("");

    if c.persist_quote_proof_wires {
        w.block(
            r###"
            |# Pedersen blindings committed when each Maker registered its
            |# policy. They are inputs, not fresh prover randomness: using new
            |# blindings here would prove a policy invented after the RFQ.
            "###,
        );
        for field in [
            "ask_level",
            "spread",
            "slope",
            "invcoef",
            "inv",
            "maxqty",
            "expiry",
            "active",
            "use_ref",
        ] {
            w.push(format!("QPB_{field} = Array(M, sint)"));
        }
        w.push("for i in range(M):");
        for field in [
            "ask_level",
            "spread",
            "slope",
            "invcoef",
            "inv",
            "maxqty",
            "expiry",
            "active",
            "use_ref",
        ] {
            w.push(format!("    QPB_{field}[i] = secret_input()"));
        }
        w.push("");
    }

    if checking {
        w.block(
            r###"
            |
            |# ---- input check, one opening per node ----------------------------
            |# The public commitment verifier is the other half. It combines the
            |# same powers of the same rho into the share
            |# commitments `roles.Dealing` already publishes, so a failing opening
            |# names a node from data anybody has.
            |_rho = sint.get_random_int(CHALLENGE_BITS).reveal()
            |print_ln('QOMM_CHALLENGE=%s', _rho)
            |for _p in range(N_PARTIES):
            |    _c = cint(1)
            |    _acc = sint(0)
            |    for _k in range(N_CHECKED):
            |        _c = _c * _rho
            |        _acc = _acc + check_store[_p][_k] * _c
            |    # the mask is this node's own input and is not split, which is
            |    # why it hides with one uniform field element rather than the
            |    # width budget the integer version needed
            |    _acc = _acc + sint.get_input_from(_p)
            |    print_ln('QOMM_PER_PARTY_CHECK_0_%s=%s', _p, _acc.reveal())
            |
            "###,
        );
    } else if c.input_check {
        w.block(
            r###"
            |
            |# ---- input check: one random linear combination -------------------
            |# The coefficients are public and derived from the commitments the
            |# dealer published, so a node choosing what to substitute cannot see
            |# them first. Public times secret is local, so the combination costs
            |# no communication at all; the opening below is the whole price.
            |# The public commitment verifier combines the same coefficients into
            |# the commitments and checks this opening against them.
            |# Repetition rather than wider coefficients: at 127 bits the budget is
            |# challenge + hiding <= 41, so soundness is bought back by opening
            |# several independent combinations, which cost one round together
            |# because none of them waits on another.
            "###,
        );
        w.push(format!(
            "CHECK_COEFF = {}",
            mp_spdz_list(&check_coefficients)
        ));
        w.push(format!("CHECK_REPEATS = {}", c.check_repeats));
        w.block(
            r###"
            |check_masks = [secret_input() for _ in range(CHECK_REPEATS)]
            |for _r in range(CHECK_REPEATS):
            |    combination = check_masks[_r]
            |    _k = 0
            |    for i in range(M):
            "###,
        );
        for field in FIELDS {
            w.push(format!(
                "        combination = combination + col_{field}[i] * CHECK_COEFF[(_r * 7919 + _k) % len(CHECK_COEFF)]"
            ));
            w.push("        _k += 1");
        }
        w.push("    print_ln('QOMM_INPUT_CHECK_%s=%s', _r, combination.reveal())");
        w.push("");
    }

    w.block(
        r###"
        |idx = Array(M, sint)
        |for i in range(M):
        |    idx[i] = sint(i)
        |wide_idx = Array(M * N_REQ, sint)
        |for r in range(N_REQ):
        |    for i in range(M):
        |        wide_idx[r * M + i] = sint(i)
        |
        |
        "###,
    );
    if c.reference == Reference::None {
        w.block(
            r###"
            |# No reference price. The maker carries the whole level in `mid` and
            |# re-deals it as often as it likes; nothing here is standing.
            |ref_secret_per_request = None
            |ref_secret = None
            |asset_onehot = [req_asset[0] == sint(a) for a in range(N_ASSETS)]
            |
            "###,
        );
    } else {
        w.push("# ---- oblivious reference-price lookup ----");
    }
    // including its reassignment after the `reference == none` prelude.
    w.block(
        r###"
        |# ref = sum_a (asset == a) * REF_TABLE[a]. Each term multiplies a secret
        |# bit by a public constant, which costs nothing, so the whole lookup is
        |# N_ASSETS equality tests in one layer. Selecting the row publicly would
        |# announce which market the request is for, which is the thing to avoid.
        |ref_secret_per_request = Array(N_REQ, sint)
        |asset_onehot = None
        |for r in range(N_REQ):
        |    onehot = [req_asset[r] == sint(a) for a in range(N_ASSETS)]
        |    if r == 0:
        |        asset_onehot = onehot
        |    acc = onehot[0] * REF_TABLE[0]
        |    for a in range(1, N_ASSETS):
        |        acc = acc + onehot[a] * REF_TABLE[a]
        |    ref_secret_per_request[r] = acc
        |ref_secret = ref_secret_per_request[0]
        |
        "###,
    );
    if c.public_maker_assets {
        w.block(
            r###"
            |# gather the one-hot bit for each maker's publicly known market
            |asset_gate = Array(M, sint)
            |for i in range(M):
            |    asset_gate[i] = asset_onehot[MAKER_ASSET[i]]
            |
            "###,
        );
    }
    w.block(
        r###"
        |# One job serves N_REQ requests. Every per-maker vector is widened to
        |# N_REQ*M so the comparison layers are shared: rounds are a property of the
        |# job, not of the request, which is what makes batching worth doing.
        |WIDE = N_REQ * M
        |def tile_makers(vec):
        |    out = Array(WIDE, sint)
        |    for r in range(N_REQ):
        |        out.assign(vec, r * M)
        |    return out.get_vector()
        |def spread_request(arr):
        |    out = Array(WIDE, sint)
        |    for r in range(N_REQ):
        |        out.assign(arr[r].expand_to_vector(M), r * M)
        |    return out.get_vector()
        |qty_v = spread_request(req_qty)
        |asset_v = spread_request(req_asset)
        |dir_v = spread_request(req_dir)
        |
        |inv_state = Array(M, sint)
        |inv_state.assign(col_inv.get_vector())
        |
        |
        |def pack_key(cost, index_vec):
        |    """Pack the tie-breaking index into the low bits.
        |
        |    Two things fall out of this. Keys become unique, so a strict comparison
        |    is enough and no tie-breaking logic is needed. And the winning index
        |    travels inside the value, so the tournament no longer has to carry a
        |    second secret array and pay a second multiplication at every level.
        |    """
        |    return cost * M + index_vec
        |
        |
        |# The packed key is only ever unpacked after it is opened, by whoever
        |# received it. Doing it in secret would cost a division and a modulo.
        |
        |
        |def min_tree(keys, n):
        |    """Binary tournament: depth log2(n), one comparison and one select per level."""
        |    cur = Array(n, sint)
        |    cur.assign(keys)
        |    size = n
        |    while size > 1:
        |        half = size // 2
        |        a = cur.get_vector(0, half)
        |        b = cur.get_vector(half, half)
        |        cur.assign((a < b).if_else(a, b), 0)
        |        size = half
        |    return cur[0]
        |
        |
        |def min_kary(keys, n, arity):
        |    """Arity-k tournament: depth log_k(n) levels, k(k-1) comparisons per group.
        |
        |    Trades comparison count for circuit depth. Depth costs round trips, which
        |    are the binding constraint over a wide area; comparison count costs
        |    bandwidth, which is not. The best arity therefore depends on the link, so
        |    it is left as a measured parameter rather than a fixed choice.
        |    """
        |    cur = Array(n, sint)
        |    cur.assign(keys)
        |    size = n
        |    while size > 1:
        |        size = kary_level(cur, size, arity)
        |    return cur[0]
        |
        |
        |def kary_level(cur, size, arity):
        |    """One level, in place. Split out so the fill fold can stop one short."""
        |    a = min(arity, size)
        |    groups = size // a
        |    # block p holds the p-th member of every group, so each block is contiguous
        |    blocks = [cur.get_vector(p * groups, groups) for p in range(a)]
        |    ranks = []
        |    for p in range(a):
        |        rank = None
        |        for q in range(a):
        |            if p == q:
        |                continue
        |            less = blocks[q] < blocks[p]
        |            rank = less if rank is None else rank + less
        |        ranks.append(rank)
        |    # the rank is at most arity-1, so the equality does not need the
        |    # full key width. Comparing at full width was costing more rounds
        |    # than the extra tree level it was supposed to remove.
        |    rank_bits = max(2, (a - 1).bit_length() + 1)
        |    winner = None
        |    for p in range(a):
        |        selected = ranks[p].equal(0, rank_bits)
        |        term = selected * blocks[p]
        |        winner = term if winner is None else winner + term
        |    cur.assign(winner, 0)
        |    return groups
        |
        |
        |def argmin(keys, n):
        "###,
    );
    if c.argmin_arity <= 2 {
        w.push("    return min_tree(keys, n)");
    } else {
        w.push(format!("    return min_kary(keys, n, {})", c.argmin_arity));
    }
    w.push("");
    w.push("");

    if c.binding_limit {
        w.block(
            r###"
            |def argmin_fill(keys, n, limit):
            |    """The winner and whether it beats the limit, at the same depth.
            |
            |    `min(a, b) <= L` is decided by `a <= L` and `b <= L`, and both
            |    operands exist before the last tournament level runs. So the last
            |    level compares three pairs in one layer where it used to compare
            |    one, and selects twice in one layer where it used to select once.
            |    The fill comparison stops being a standalone comparison paying
            |    full depth after the tournament and becomes extra lanes inside a
            |    layer that was going to run anyway.
            |
            |    Comparisons here are `<=` where the tournament used `<`. The two
            |    differ only on a tie, and keys cannot tie: a key is
            |    `cost * WIDE + index` and the index is unique per lane.
            |    """
            |    cur = Array(n, sint)
            |    cur.assign(keys)
            |    size = n
            "###,
        );
        if c.argmin_arity <= 2 {
            w.block(
                r###"
                |    while size > 2:
                |        half = size // 2
                |        a = cur.get_vector(0, half)
                |        b = cur.get_vector(half, half)
                |        cur.assign((a <= b).if_else(a, b), 0)
                |        size = half
                |    if size == 1:
                |        # a single maker leaves no last level to fold into
                |        return cur[0], cur[0] <= limit
                |    left = Array(3, sint)
                |    left.assign_vector(cur.get_vector(0, 1), 0)
                |    left.assign_vector(cur.get_vector(0, 1), 1)
                |    left.assign_vector(cur.get_vector(1, 1), 2)
                |    right = Array(3, sint)
                |    right.assign_vector(cur.get_vector(1, 1), 0)
                |    right.assign_vector(limit, 1)
                |    right.assign_vector(limit, 2)
                |    bits = Array(3, sint)
                |    bits.assign(left.get_vector() <= right.get_vector())
                |    first = bits[0]
                |    return (first.if_else(cur[0], cur[1]),
                |            first.if_else(bits[1], bits[2]))
                "###,
            );
        } else {
            w.push(format!("    arity = {}", c.argmin_arity));
            w.block(
                r###"
                |    while size > arity:
                |        size = kary_level(cur, size, arity)
                |    if size == 1:
                |        return cur[0], cur[0] <= limit
                |    # The last level with one more comparison per finalist. Cell
                |    # (p, q) of the square holds `finalists[q] <= finalists[p]`
                |    # off the diagonal, which is p's rank term, and
                |    # `finalists[p] <= limit` on it, which is whether p fills. All
                |    # of them in one layer, then the two selects in the next.
                |    finalists = [cur.get_vector(p, 1) for p in range(size)]
                |    left = Array(size * size, sint)
                |    right = Array(size * size, sint)
                |    for p in range(size):
                |        for q in range(size):
                |            left.assign_vector(finalists[q], p * size + q)
                |            right.assign_vector(finalists[p] if p != q else limit,
                |                                p * size + q)
                |    cell = Array(size * size, sint)
                |    cell.assign(left.get_vector() <= right.get_vector())
                |    rank_bits = max(2, (size - 1).bit_length() + 1)
                |    winner = None
                |    filled = None
                |    for p in range(size):
                |        rank = None
                |        for q in range(size):
                |            if p == q:
                |                continue
                |            term = cell[p * size + q]
                |            rank = term if rank is None else rank + term
                |        chosen = rank.equal(0, rank_bits)
                |        prize = chosen * finalists[p]
                |        fits = chosen * cell[p * size + p]
                |        winner = prize if winner is None else winner + prize
                |        filled = fits if filled is None else filled + fits
                |    return winner, filled
                "###,
            );
        }
        w.push("");
        w.push("");
    }

    if c.persist_wires {
        w.block(
            r###"
            |# Where the joint prover reads the wires from. The vectors inside
            |# `quote_layer` are local to it, and the proof is about all of them,
            |# so they are parked here rather than returned --- which would change
            |# a signature three other modes share.
            "###,
        );
        for name in [
            "ask_level",
            "spread",
            "slope",
            "invcoef",
            "inv",
            "maxqty",
            "expiry",
            "active",
            "depth",
            "skew",
            "ask",
            "bid",
            "fits",
            "ok",
            "fits_margin",
            "fresh_margin",
            "fresh_bit",
            "fits_product",
            "fresh_product",
            "both",
            "gated",
            "cost",
        ] {
            w.push(format!("W_{name} = Array(WIDE, sint)"));
        }
        w.push("W_key = Array(WIDE, sint)");
        w.push("W_qty = Array(1, sint)");
        w.push("");
    }

    w.block(
        r###"
        |def quote_layer(inv_vec, ref_secret, now_t):
        |    """One evaluation of P_i(x, s_i, m_t) for every market maker at once."""
        |    ask_level = tile_makers(col_ask_level.get_vector())
        |    spread = tile_makers(col_spread.get_vector())
        |    slope = tile_makers(col_slope.get_vector())
        |    invcoef = tile_makers(col_invcoef.get_vector())
        |    maxqty = tile_makers(col_maxqty.get_vector())
        |    expiry = tile_makers(col_expiry.get_vector())
        |    active = tile_makers(col_active.get_vector())
        |    asset_mm = tile_makers(col_asset.get_vector())
        |    # Layer 1 is emitted from the venue-approved price-policy DSL.
        |    # Its exact rule digest is checked before the source is compiled.
        "###,
    );
    if c.reference == Reference::Anchored {
        w.push("    use_ref = tile_makers(col_use_ref.get_vector())");
    }
    let (policy_digest, assignments) = policy_assignments(c)?;
    w.push(format!("    {POLICY_RULE_DIGEST_MARKER}{policy_digest}"));
    for assignment in assignments {
        w.push(format!("    {assignment}"));
    }
    if c.persist_wires {
        for name in [
            "ask_level",
            "spread",
            "slope",
            "invcoef",
            "maxqty",
            "expiry",
            "active",
            "depth",
            "skew",
            "ask",
            "bid",
        ] {
            w.push(format!("    W_{name}.assign({name})"));
        }
        w.block(
            r###"
            |    W_inv.assign(tile_makers(inv_vec))
            |    W_fits_margin.assign(maxqty - qty_v)
            |    W_fresh_margin.assign(expiry - sint(now_t) - 1)
            "###,
        );
    }
    if matches!(c.stop_after, StopAfter::Price | StopAfter::Direction) {
        w.block(
            r###"
            |    # Cut before the eligibility layer. Nothing below this line is built,
            |    # so the rounds this circuit costs are the price layer's own.
            |    return ask, bid, None, maxqty
            "###,
        );
    } else {
        w.push(
            "    # layer 2: eligibility (3 SIMD comparisons + 3 SIMD multiplications, depth 1+cmp)",
        );
        if c.public_maker_assets {
            w.block(
                r###"
                |    # The market each maker serves is public business information; only the
                |    # *user's* asset is secret. So the asset gate is a public index into the
                |    # secret one-hot vector, which costs no communication at all, instead of
                |    # an equality test per maker.
                |    g_asset = tile_makers(asset_gate.get_vector())
                "###,
            );
        } else {
            w.push("    g_asset = asset_mm == asset_v");
        }
        w.push("    g_qty = qty_v <= maxqty");
        if c.persist_wires {
            w.block(
                r###"
                |    W_fits.assign(g_qty)
                |    _fresh_bit = expiry > sint(now_t)
                |    W_fresh_bit.assign(_fresh_bit)
                |    # holds * value for each gate: one multiplication each, and
                |    # the wire a product proof is about
                |    W_fits_product.assign(g_qty * (maxqty - qty_v))
                |    W_fresh_product.assign(_fresh_bit * (expiry - sint(now_t) - 1))
                |    W_both.assign(g_qty * _fresh_bit)
                "###,
            );
        }
        if c.audit_gates {
            w.block(
                r###"
                |    # The expiry is proved at registration: the auditor refuses an audit
                |    # unless `now < expiry <= now + horizon`, so re-checking it here pays
                |    # for the same fact twice.
                |    #
                |    # The active flag is *not*. The audit proves it is a bit and never
                |    # that it is set, and it could not usefully prove it is set --- a
                |    # committed one is a public one, and whether a maker is quoting at
                |    # all is what the commitment is hiding. So it stays in the circuit.
                |    # This flag used to drop it too, and with it dropped a maker that had
                |    # withdrawn still won tournaments.
                |    ok = active * g_asset * g_qty
                "###,
            );
            if c.persist_wires {
                w.push("    W_ok.assign(ok)");
            }
        } else {
            w.block(
                r###"
                |    g_exp = expiry > sint(now_t)
                |    ok = active * g_asset * g_qty * g_exp
                "###,
            );
            if c.persist_wires {
                w.push("    W_ok.assign(ok)");
            }
        }
        w.push("    return ask, bid, ok, maxqty");
    }
    w.push("");
    w.push("");

    if c.disclose == Disclosure::Threshold {
        w.push(format!("BAND = {} * REF_MID // 10000", c.band_bps));
        w.push(format!("THRESHOLD_K = {}", c.threshold_k));
        w.push(format!("THRESHOLD_V = {}", c.threshold_v));
        w.block(
            r###"
            |
            |
            |def threshold_disclosure(ask, ok, maxqty, ref_secret):
            |    """ZK-style threshold statement: >=K independent MMs, >=V size, inside the band."""
            |    lo = ask >= (ref_secret - BAND).expand_to_vector(M)
            |    hi = ask <= (ref_secret + BAND).expand_to_vector(M)
            |    in_band = lo * hi
            |    elig = ok * in_band
            |    size_v = elig * maxqty
            |    elig_a = Array(M, sint)
            |    elig_a.assign(elig)
            |    size_a = Array(M, sint)
            |    size_a.assign(size_v)
            |    n_ok = elig_a[0]
            |    vol = size_a[0]
            |    for i in range(1, M):
            |        n_ok = n_ok + elig_a[i]
            |        vol = vol + size_a[i]
            |    return (n_ok >= sint(THRESHOLD_K)) * (vol >= sint(THRESHOLD_V))
            |
            |
            "###,
        );
    }

    match c.mode {
        Mode::Rfq => {
            w.push("ask, bid, ok, maxqty = quote_layer(inv_state.get_vector(), ref_secret, NOW_T)");
            if c.stop_after == StopAfter::Price {
                w.block(
                    r###"
                    |# stage cut: open one value that both priced sides feed
                    |stage_out = Array(WIDE, sint)
                    |stage_out.assign(ask + bid)
                    |stage_out.get_vector().reveal_to(0)
                    "###,
                );
                return Ok(w.finish());
            }
            w.push("# direction stays secret: minimise the user's cost on whichever side applies");
            w.push("cost = dir_v.if_else(-bid, ask)");
            if c.stop_after == StopAfter::Direction {
                w.block(
                    r###"
                    |# stage cut: the selection is built, the gates are not
                    |stage_out = Array(WIDE, sint)
                    |stage_out.assign(cost)
                    |stage_out.get_vector().reveal_to(0)
                    "###,
                );
                return Ok(w.finish());
            }
            if c.persist_wires {
                w.block(
                    r###"
                    |W_cost.assign(cost)
                    |W_gated.assign(ok * (cost - sint(LARGE)))
                    |W_qty[0] = qty_v.get_vector(0, 1)
                    "###,
                );
            }
            w.push("cost = ok.if_else(cost, sint(LARGE))");
            if c.stop_after == StopAfter::Gates {
                w.block(
                    r###"
                    |# stage cut: everything but the tournament
                    |stage_out = Array(WIDE, sint)
                    |stage_out.assign(cost)
                    |stage_out.get_vector().reveal_to(0)
                    "###,
                );
                return Ok(w.finish());
            }
            w.block(
                r###"
                |wide_keys = Array(WIDE, sint)
                |wide_keys.assign(pack_key(cost, wide_idx.get_vector()))
                "###,
            );
            if c.persist_wires {
                if c.persist_quote_proof_wires {
                    w.push(
                        "# Bias signed costs for the public u64 proof opening; order is unchanged",
                    );
                    w.push("W_key.assign(wide_keys.get_vector() + LARGE * M)");
                } else {
                    w.push("W_key.assign(wide_keys.get_vector())");
                }
            }
            if c.binding_limit {
                w.block(
                    r###"
                    |# The comparison is against the packed key, not the price. Each
                    |# request has an independent M-maker lane and `pack_key` uses
                    |# `cost*M + maker`; N_REQ must never change the price scale.
                    |# Therefore `cost <= L` is exactly `key <= L*M + M-1`.
            |# Buy: ask <= maximum. Sell: -bid <= -minimum. Keep the
            |# comparison in the same signed-cost domain used by argmin.
            |cost_limit = u_dir.if_else(-u_limit, u_limit)
            |limit_key = cost_limit * M + (M - 1)
                    |# The fill comparison rides the tournament's last layer rather
                    |# than running after it. Measured at +9 rounds standalone.
                    |raw_best_key, raw_fill = argmin_fill(wide_keys.get_vector(0, M), M,
                    |                                     limit_key)
                    |# A cover lane must execute the identical circuit but must
                    |# not leave a usable quote or proof witness.  The client
                    |# still supplies random output masks, so neither an MPC
                    |# node nor the coordinator can recognize the zero payload.
                    |best_key = raw_best_key * u_is_real
                    |fill = raw_fill * u_is_real
                    "###,
                );
            } else {
                w.push("raw_best_key = argmin(wide_keys.get_vector(0, M), M)");
                w.push("best_key = raw_best_key * u_is_real");
            }
            w.block(
                r###"
                |for r in range(1, N_REQ):
                |    (argmin(wide_keys.get_vector(r * M, M), M) * u_is_real + u_mask).reveal()
                |# one opened value carries both the winning price and the winning
                |# maker, under the trader's mask
                "###,
            );
            if c.binding_limit {
                w.block(
                    r###"
                    |# Both outputs go back under the trader's masks. Revealing `fill`
                    |# in the clear would say which slots traded, which is precisely
                    |# what the `is_real` cover traffic exists to hide --- a public
                    |# fill bit would mark every cover slot as cover.
                    |print_ln('QOMM_MASKED_FILL=%s', (fill + fill_mask).reveal())
                    |print_ln('QOMM_MASKED_KEY=%s', (fill * best_key + u_mask).reveal())
                    "###,
                );
            } else {
                w.push("print_ln('QOMM_MASKED_KEY=%s', (best_key + u_mask).reveal())");
            }
            w.block(
                r###"
                |
                |# Each node keeps its *share* of the answer, written where the joint
                |# prover reads it. This is the binding the design has been missing:
                |# the quote proof is assembled from shares, and until now those
                |# shares were supplied to the prover separately from the ones the
                |# circuit computed on, so nothing said they were the same numbers.
                |# Writing them here and reading them there makes it one value
                |# crossing a named interface rather than two that agree.
                "###,
            );
            if c.persist_wires {
                if c.persist_zkpi_wires {
                    w.block(
                        r###"
                        |# Select the positive settlement price without opening the
                        |# packed winner. The packed key uses the signed user cost
                        |# (`ask` for buy, `-bid` for sell); zkPI always carries the
                        |# positive cash price.
                        |settlement_prices = dir_v.if_else(bid, ask)
                        |winner_flags = (wide_keys.get_vector(0, M) == best_key) * u_is_real.expand_to_vector(M)
                        |zkpi_price = winner_flags[0] * settlement_prices[0]
                        |for _m in range(1, M):
                        |    zkpi_price = zkpi_price + winner_flags[_m] * settlement_prices[_m]
                        |
                        |# Blindings and bit relations are generated *inside* the
                        |# malicious-secure MPC. Every Persistence file receives
                        |# only that party's Shamir evaluation. No later issuer is
                        |# asked to recreate these values from a clear quote.
                        |zkpi_qty_blinding = u_qty_blinding
                        |zkpi_price_blinding = sint.get_random()
                        |zkpi_qty_bits = W_qty[0].bit_decompose(ZKPI_AMOUNT_BITS)
                        |zkpi_price_bits = zkpi_price.bit_decompose(ZKPI_PRICE_BITS)
                        |zkpi_qty_bit_blindings = [sint.get_random() for _ in range(ZKPI_AMOUNT_BITS)]
                        |zkpi_price_bit_blindings = [sint.get_random() for _ in range(ZKPI_PRICE_BITS)]
                        |zkpi_qty_bit_cross = [zkpi_qty_bit_blindings[_b] * (1 - zkpi_qty_bits[_b])
                        |                      for _b in range(ZKPI_AMOUNT_BITS)]
                        |zkpi_price_bit_cross = [zkpi_price_bit_blindings[_b] * (1 - zkpi_price_bits[_b])
                        |                        for _b in range(ZKPI_PRICE_BITS)]
                        "###,
                    );
                    if c.persist_dvp_wires {
                        w.block(
                            r###"
                            |# Select the winning Maker's venue-specific account
                            |# handle without opening either the winner index or
                            |# the scalar. Its Shamir evaluation is persisted in
                            |# the zkPI prefix so proof nodes can bind the final
                            |# payment instruction before authorizing it.
                            |selected_maker_handle_scalar = winner_flags[0] * dvp_maker_handle_scalars[0]
                            |for _m in range(1, M):
                            |    selected_maker_handle_scalar = selected_maker_handle_scalar + winner_flags[_m] * dvp_maker_handle_scalars[_m]
                            "###,
                        );
                    } else {
                        w.block(
                            r###"
                            |# The zkPI-only test circuit has no DvP account
                            |# registry. Keep the same persistence ABI with
                            |# deterministic pseudonymous fixture handles.
                            |selected_maker_handle_scalar = winner_flags[0] * 21
                            |for _m in range(1, M):
                            |    selected_maker_handle_scalar = selected_maker_handle_scalar + winner_flags[_m] * (21 + _m)
                            "###,
                        );
                    }
                    if c.binding_limit {
                        w.block(
                            r###"
                            |# Joint proof witness for the signed hidden price
                            |# limit. Buy: limit - quote. Sell: quote - limit.
                            |# A non-filling lane cannot create a valid bounded
                            |# proof and therefore cannot reach auto-settlement.
                            |zkpi_limit_difference = u_dir.if_else(zkpi_price - u_limit,
                            |                                          u_limit - zkpi_price)
                            |zkpi_limit_difference_blinding = u_dir.if_else(
                            |    zkpi_price_blinding - u_limit_blinding,
                            |    u_limit_blinding - zkpi_price_blinding)
                            |zkpi_limit_difference_bits = zkpi_limit_difference.bit_decompose(ZKPI_PRICE_BITS)
                            |zkpi_limit_difference_bit_blindings = [sint.get_random() for _ in range(ZKPI_PRICE_BITS)]
                            |zkpi_limit_difference_bit_cross = [
                            |    zkpi_limit_difference_bit_blindings[_b] * (1 - zkpi_limit_difference_bits[_b])
                            |    for _b in range(ZKPI_PRICE_BITS)]
                            "###,
                        );
                    } else {
                        w.block(
                            r###"
                            |# Preserve one persistence layout for all zkPI
                            |# circuits. A venue may not interpret this zero
                            |# witness as a signed-limit proof unless the
                            |# approved circuit has binding_limit enabled.
                            |zkpi_limit_difference = sint(0)
                            |zkpi_limit_difference_blinding = sint(0)
                            |zkpi_limit_difference_bits = [sint(0) for _ in range(ZKPI_PRICE_BITS)]
                            |zkpi_limit_difference_bit_blindings = [sint(0) for _ in range(ZKPI_PRICE_BITS)]
                            |zkpi_limit_difference_bit_cross = [sint(0) for _ in range(ZKPI_PRICE_BITS)]
                            "###,
                        );
                    }
                    if c.persist_dvp_wires {
                        w.block(
                            r###"
                            |
                            |# The cash leg and both unused reservation amounts
                            |# remain secret. Their blindings and every bit
                            |# relation are generated in this same MPC execution,
                            |# so no later process has to receive both parties'
                            |# openings in order to build the DvP proof.
                            |selected_maker_securities_reserve = winner_flags[0] * dvp_maker_securities_reserves[0]
                            |selected_maker_securities_blinding = winner_flags[0] * dvp_maker_securities_blindings[0]
                            |selected_maker_cash_reserve = winner_flags[0] * dvp_maker_cash_reserves[0]
                            |selected_maker_cash_blinding = winner_flags[0] * dvp_maker_cash_blindings[0]
                            |for _m in range(1, M):
                            |    selected_maker_securities_reserve = selected_maker_securities_reserve + winner_flags[_m] * dvp_maker_securities_reserves[_m]
                            |    selected_maker_securities_blinding = selected_maker_securities_blinding + winner_flags[_m] * dvp_maker_securities_blindings[_m]
                            |    selected_maker_cash_reserve = selected_maker_cash_reserve + winner_flags[_m] * dvp_maker_cash_reserves[_m]
                            |    selected_maker_cash_blinding = selected_maker_cash_blinding + winner_flags[_m] * dvp_maker_cash_blindings[_m]
                            |
                            |dvp_cash = W_qty[0] * zkpi_price
                            |dvp_cash_blinding = sint.get_random()
                            |dvp_product_cross = dvp_cash_blinding - zkpi_qty_blinding * zkpi_price
                            |# user buys (dir=0): Maker delivers exactly the
                            |# requested securities quantity and Taker's maximum
                            |# cash reserve covers the hidden price. user sells
                            |# (dir=1): Taker securities cover the quantity and
                            |# Maker delivers exactly the MPC-computed cash.
                            |# The larger standing Maker pool is split separately
                            |# below, so one RFQ cannot lock the whole policy cap.
                            |dvp_direction = req_dir[0]
                            |dvp_securities_reserve = dvp_direction.if_else(dvp_taker_securities_reserve,
                            |                                                   W_qty[0])
                            |dvp_securities_reserve_blinding = dvp_direction.if_else(dvp_taker_securities_blinding,
                            |                                                            zkpi_qty_blinding)
                            |dvp_cash_reserve = dvp_direction.if_else(dvp_cash,
                            |                                             dvp_taker_cash_reserve)
                            |dvp_cash_reserve_blinding = dvp_direction.if_else(dvp_cash_blinding,
                            |                                                      dvp_taker_cash_blinding)
                            |dvp_securities_remainder = dvp_securities_reserve - W_qty[0]
                            |dvp_securities_remainder_blinding = dvp_securities_reserve_blinding - zkpi_qty_blinding
                            |dvp_cash_remainder = dvp_cash_reserve - dvp_cash
                            |dvp_cash_remainder_blinding = dvp_cash_reserve_blinding - dvp_cash_blinding
                            |# This is not either DvP refund. It is the unallocated
                            |# balance of the selected Maker's policy covenant.
                            |dvp_maker_pool_before = dvp_direction.if_else(selected_maker_cash_reserve,
                            |                                                  selected_maker_securities_reserve)
                            |dvp_maker_pool_before_blinding = dvp_direction.if_else(selected_maker_cash_blinding,
                            |                                                           selected_maker_securities_blinding)
                            |dvp_maker_delivery = dvp_direction.if_else(dvp_cash, W_qty[0])
                            |dvp_maker_delivery_blinding = dvp_direction.if_else(dvp_cash_blinding,
                            |                                                        zkpi_qty_blinding)
                            |dvp_maker_pool_remainder = dvp_maker_pool_before - dvp_maker_delivery
                            |dvp_maker_pool_remainder_blinding = dvp_maker_pool_before_blinding - dvp_maker_delivery_blinding
                            |dvp_securities_bits = dvp_securities_remainder.bit_decompose(DVP_REMAINDER_BITS)
                            |dvp_cash_bits = dvp_cash_remainder.bit_decompose(DVP_REMAINDER_BITS)
                            |dvp_maker_pool_bits = dvp_maker_pool_remainder.bit_decompose(DVP_REMAINDER_BITS)
                            |dvp_securities_bit_blindings = [sint.get_random() for _ in range(DVP_REMAINDER_BITS)]
                            |dvp_cash_bit_blindings = [sint.get_random() for _ in range(DVP_REMAINDER_BITS)]
                            |dvp_maker_pool_bit_blindings = [sint.get_random() for _ in range(DVP_REMAINDER_BITS)]
                            |dvp_securities_bit_cross = [dvp_securities_bit_blindings[_b] * (1 - dvp_securities_bits[_b])
                            |                            for _b in range(DVP_REMAINDER_BITS)]
                            |dvp_cash_bit_cross = [dvp_cash_bit_blindings[_b] * (1 - dvp_cash_bits[_b])
                            |                    for _b in range(DVP_REMAINDER_BITS)]
                            |dvp_maker_pool_bit_cross = [dvp_maker_pool_bit_blindings[_b] * (1 - dvp_maker_pool_bits[_b])
                            |                          for _b in range(DVP_REMAINDER_BITS)]
                            "###,
                        );
                    }
                    if c.persist_quote_proof_wires {
                        w.block(
                            r###"
                            |
                            |# Complete quote-proof handoff.  Every blinding and
                            |# relation below is generated or evaluated inside
                            |# the same malicious-secure MPC execution as the
                            |# quote. Persistence writes only this party's share.
                            |quote_depth_blindings = [sint.get_random() for _m in range(M)]
                            |quote_skew_blindings = [sint.get_random() for _m in range(M)]
                            |quote_fits_bit_blindings = [sint.get_random() for _m in range(M)]
                            |quote_fits_product_blindings = [sint.get_random() for _m in range(M)]
                            |quote_fresh_bit_blindings = [sint.get_random() for _m in range(M)]
                            |quote_fresh_product_blindings = [sint.get_random() for _m in range(M)]
                            |quote_both_blindings = [sint.get_random() for _m in range(M)]
                            |quote_ok_blindings = [sint.get_random() for _m in range(M)]
                            |quote_gated_blindings = [sint.get_random() for _m in range(M)]
                            |
                            |quote_anchor_blindings = []
                            |quote_cost_blindings = []
                            |quote_depth_cross = []
                            |quote_skew_cross = []
                            |quote_fits_bit_cross = []
                            |quote_fits_product_cross = []
                            |quote_fresh_bit_cross = []
                            |quote_fresh_product_cross = []
                            |quote_active_cross = []
                            |quote_reference_cross = []
                            |quote_both_cross = []
                            |quote_ok_cross = []
                            |quote_gated_cross = []
                            |quote_fits_witness = []
                            |quote_fits_witness_blindings = []
                            |quote_fits_witness_bits = []
                            |quote_fits_witness_bit_blindings = []
                            |quote_fits_witness_bit_cross = []
                            |quote_fresh_witness = []
                            |quote_fresh_witness_blindings = []
                            |quote_fresh_witness_bits = []
                            |quote_fresh_witness_bit_blindings = []
                            |quote_fresh_witness_bit_cross = []
                            |quote_key_blindings = []
                            |
                            |for _m in range(M):
                            |    _anchor_blinding = QPB_ask_level[_m] + QPB_use_ref[_m] * ref_secret
                            |    _ask_blinding = _anchor_blinding + quote_depth_blindings[_m] + quote_skew_blindings[_m]
                            |    _bid_blinding = _anchor_blinding - QPB_spread[_m] - quote_depth_blindings[_m] + quote_skew_blindings[_m]
                            |    _cost_blinding = req_dir[0].if_else(-_bid_blinding, _ask_blinding)
                            |    quote_anchor_blindings.append(_anchor_blinding)
                            |    quote_cost_blindings.append(_cost_blinding)
                            |    quote_depth_cross.append(quote_depth_blindings[_m] - QPB_slope[_m] * W_qty[0])
                            |    quote_skew_cross.append(quote_skew_blindings[_m] - QPB_invcoef[_m] * W_inv[_m])
                            |    quote_fits_bit_cross.append(quote_fits_bit_blindings[_m] * (1 - W_fits[_m]))
                            |    quote_fits_product_cross.append(quote_fits_product_blindings[_m] - quote_fits_bit_blindings[_m] * W_fits_margin[_m])
                            |    quote_fresh_bit_cross.append(quote_fresh_bit_blindings[_m] * (1 - W_fresh_bit[_m]))
                            |    quote_fresh_product_cross.append(quote_fresh_product_blindings[_m] - quote_fresh_bit_blindings[_m] * W_fresh_margin[_m])
                            |    quote_active_cross.append(QPB_active[_m] * (1 - W_active[_m]))
                            |    quote_reference_cross.append(QPB_use_ref[_m] * (1 - col_use_ref[_m]))
                            |    quote_both_cross.append(quote_both_blindings[_m] - quote_fits_bit_blindings[_m] * W_fresh_bit[_m])
                            |    _effective_active = W_active[_m] * asset_gate[_m]
                            |    quote_ok_cross.append(quote_ok_blindings[_m] - quote_both_blindings[_m] * _effective_active)
                            |    quote_gated_cross.append(quote_gated_blindings[_m] - quote_ok_blindings[_m] * (W_cost[_m] - sint(LARGE)))
                            |
                            |    _fits_blinding = QPB_maxqty[_m] - zkpi_qty_blinding
                            |    _fits_witness = 2 * W_fits_product[_m] - W_fits_margin[_m] + W_fits[_m] - 1
                            |    _fits_witness_blinding = 2 * quote_fits_product_blindings[_m] - _fits_blinding + quote_fits_bit_blindings[_m]
                            |    _fits_bits = _fits_witness.bit_decompose(QUOTE_ELIGIBILITY_BITS)
                            |    _fits_bit_blindings = [sint.get_random() for _b in range(QUOTE_ELIGIBILITY_BITS)]
                            |    _fits_bit_cross = [_fits_bit_blindings[_b] * (1 - _fits_bits[_b]) for _b in range(QUOTE_ELIGIBILITY_BITS)]
                            |    quote_fits_witness.append(_fits_witness)
                            |    quote_fits_witness_blindings.append(_fits_witness_blinding)
                            |    quote_fits_witness_bits.append(_fits_bits)
                            |    quote_fits_witness_bit_blindings.append(_fits_bit_blindings)
                            |    quote_fits_witness_bit_cross.append(_fits_bit_cross)
                            |
                            |    _fresh_witness = 2 * W_fresh_product[_m] - W_fresh_margin[_m] + W_fresh_bit[_m] - 1
                            |    _fresh_witness_blinding = 2 * quote_fresh_product_blindings[_m] - QPB_expiry[_m] + quote_fresh_bit_blindings[_m]
                            |    _fresh_bits = _fresh_witness.bit_decompose(QUOTE_ELIGIBILITY_BITS)
                            |    _fresh_bit_blindings = [sint.get_random() for _b in range(QUOTE_ELIGIBILITY_BITS)]
                            |    _fresh_bit_cross = [_fresh_bit_blindings[_b] * (1 - _fresh_bits[_b]) for _b in range(QUOTE_ELIGIBILITY_BITS)]
                            |    quote_fresh_witness.append(_fresh_witness)
                            |    quote_fresh_witness_blindings.append(_fresh_witness_blinding)
                            |    quote_fresh_witness_bits.append(_fresh_bits)
                            |    quote_fresh_witness_bit_blindings.append(_fresh_bit_blindings)
                            |    quote_fresh_witness_bit_cross.append(_fresh_bit_cross)
                            |    quote_key_blindings.append(quote_gated_blindings[_m] * M)
                            |
                            |quote_winner_key_blinding = winner_flags[0] * quote_key_blindings[0]
                            |for _m in range(1, M):
                            |    quote_winner_key_blinding = quote_winner_key_blinding + winner_flags[_m] * quote_key_blindings[_m]
                            |quote_minimality_values = []
                            |quote_minimality_blindings = []
                            |quote_minimality_bits = []
                            |quote_minimality_bit_blindings = []
                            |quote_minimality_bit_cross = []
                            |for _m in range(M):
                            |    _difference = W_key[_m] - (best_key + LARGE * M)
                            |    _difference_blinding = quote_key_blindings[_m] - quote_winner_key_blinding
                            |    _difference_bits = _difference.bit_decompose(QUOTE_SPAN_BITS)
                            |    _difference_bit_blindings = [sint.get_random() for _b in range(QUOTE_SPAN_BITS)]
                            |    _difference_bit_cross = [_difference_bit_blindings[_b] * (1 - _difference_bits[_b]) for _b in range(QUOTE_SPAN_BITS)]
                            |    quote_minimality_values.append(_difference)
                            |    quote_minimality_blindings.append(_difference_blinding)
                            |    quote_minimality_bits.append(_difference_bits)
                            |    quote_minimality_bit_blindings.append(_difference_bit_blindings)
                            |    quote_minimality_bit_cross.append(_difference_bit_cross)
                            "###,
                        );
                    }
                }
                w.block(
                    r###"
                    |wires = [best_key, W_qty[0]]
                    |for _m in range(M):
                    |    wires += [W_ask_level[_m], W_spread[_m], W_slope[_m], W_invcoef[_m],
                    |              W_inv[_m], W_maxqty[_m], W_expiry[_m], W_active[_m],
                    |              W_depth[_m], W_skew[_m], W_ask[_m], W_bid[_m],
                    |              W_fits[_m], W_ok[_m], W_key[_m],
                    |              W_fits_margin[_m], W_fresh_margin[_m], W_fresh_bit[_m],
                    |              W_fits_product[_m], W_fresh_product[_m],
                    |              W_both[_m], W_gated[_m], W_cost[_m]]
                    "###,
                );
                if c.persist_zkpi_wires {
                    w.block(
                        r###"
                        |wires += [selected_maker_handle_scalar, zkpi_price,
                        |          zkpi_qty_blinding, zkpi_price_blinding]
                        |for _b in range(ZKPI_AMOUNT_BITS):
                        |    wires += [zkpi_qty_bits[_b], zkpi_qty_bit_blindings[_b],
                        |              zkpi_qty_bit_cross[_b]]
                        |for _b in range(ZKPI_PRICE_BITS):
                        |    wires += [zkpi_price_bits[_b], zkpi_price_bit_blindings[_b],
                        |              zkpi_price_bit_cross[_b]]
                        |wires += [zkpi_limit_difference, zkpi_limit_difference_blinding]
                        |for _b in range(ZKPI_PRICE_BITS):
                        |    wires += [zkpi_limit_difference_bits[_b],
                        |              zkpi_limit_difference_bit_blindings[_b],
                        |              zkpi_limit_difference_bit_cross[_b]]
                        "###,
                    );
                    if c.persist_dvp_wires {
                        w.block(
                            r###"
                            |wires += [dvp_cash, dvp_cash_blinding,
                            |          dvp_product_cross, dvp_securities_remainder,
                            |          dvp_securities_remainder_blinding]
                            |for _b in range(DVP_REMAINDER_BITS):
                            |    wires += [dvp_securities_bits[_b], dvp_securities_bit_blindings[_b],
                            |              dvp_securities_bit_cross[_b]]
                            |wires += [dvp_cash_remainder, dvp_cash_remainder_blinding]
                            |for _b in range(DVP_REMAINDER_BITS):
                            |    wires += [dvp_cash_bits[_b], dvp_cash_bit_blindings[_b],
                            |              dvp_cash_bit_cross[_b]]
                            |wires += [dvp_maker_pool_remainder, dvp_maker_pool_remainder_blinding]
                            |for _b in range(DVP_REMAINDER_BITS):
                            |    wires += [dvp_maker_pool_bits[_b], dvp_maker_pool_bit_blindings[_b],
                            |              dvp_maker_pool_bit_cross[_b]]
                            "###,
                        );
                    }
                    if c.persist_quote_proof_wires {
                        w.block(
                            r###"
                            |for _m in range(M):
                            |    wires += [col_use_ref[_m],
                            |              QPB_ask_level[_m], QPB_spread[_m], QPB_slope[_m],
                            |              QPB_invcoef[_m], QPB_inv[_m], QPB_maxqty[_m],
                            |              QPB_expiry[_m], QPB_active[_m], QPB_use_ref[_m],
                            |              quote_depth_blindings[_m], quote_skew_blindings[_m],
                            |              quote_fits_bit_blindings[_m], quote_fits_product_blindings[_m],
                            |              quote_fresh_bit_blindings[_m], quote_fresh_product_blindings[_m],
                            |              quote_both_blindings[_m], quote_ok_blindings[_m], quote_gated_blindings[_m],
                            |              quote_cost_blindings[_m],
                            |              quote_depth_cross[_m], quote_skew_cross[_m],
                            |              quote_fits_bit_cross[_m], quote_fits_product_cross[_m],
                            |              quote_fresh_bit_cross[_m], quote_fresh_product_cross[_m],
                            |              quote_active_cross[_m], quote_reference_cross[_m],
                            |              quote_both_cross[_m], quote_ok_cross[_m], quote_gated_cross[_m],
                            |              quote_fits_witness[_m], quote_fits_witness_blindings[_m]]
                            |    for _b in range(QUOTE_ELIGIBILITY_BITS):
                            |        wires += [quote_fits_witness_bits[_m][_b],
                            |                  quote_fits_witness_bit_blindings[_m][_b],
                            |                  quote_fits_witness_bit_cross[_m][_b]]
                            |    wires += [quote_fresh_witness[_m], quote_fresh_witness_blindings[_m]]
                            |    for _b in range(QUOTE_ELIGIBILITY_BITS):
                            |        wires += [quote_fresh_witness_bits[_m][_b],
                            |                  quote_fresh_witness_bit_blindings[_m][_b],
                            |                  quote_fresh_witness_bit_cross[_m][_b]]
                            |    wires += [quote_key_blindings[_m],
                            |              quote_minimality_values[_m], quote_minimality_blindings[_m]]
                            |    for _b in range(QUOTE_SPAN_BITS):
                            |        wires += [quote_minimality_bits[_m][_b],
                            |                  quote_minimality_bit_blindings[_m][_b],
                            |                  quote_minimality_bit_cross[_m][_b]]
                            "###,
                        );
                    }
                }
                w.push("sint.write_to_file(wires)");
            } else {
                w.push("sint.write_to_file([best_key])");
            }
            if c.range_query {
                emit_range_query(&mut w);
            }
            if c.disclose == Disclosure::Threshold {
                w.push("pub = threshold_disclosure(ask, ok, maxqty, ref_secret)");
                w.push("print_ln('QOMM_DISCLOSE=%s', pub.reveal())");
            }
        }
        Mode::Rfm => {
            w.block(
                r###"
                |ask, bid, ok, maxqty = quote_layer(inv_state.get_vector(), ref_secret, NOW_T)
                |# two-sided: the direction is never supplied at all
                |ask_cost = ok.if_else(ask, sint(LARGE))
                |bid_cost = ok.if_else(-bid, sint(LARGE))
                |ask_key = argmin(pack_key(ask_cost, idx.get_vector()), M)
                |bid_key = argmin(pack_key(bid_cost, idx.get_vector()), M)
                |print_ln('QOMM_MASKED_ASK=%s', (ask_key + u_mask).reveal())
                |print_ln('QOMM_MASKED_BID=%s', (bid_key + u_mask).reveal())
                "###,
            );
            if c.public_check {
                w.push("print_ln('QOMM_ASK_KEY=%s', ask_key.reveal())");
                w.push("print_ln('QOMM_BID_KEY=%s', bid_key.reveal())");
            }
            if c.range_query {
                emit_range_query(&mut w);
            }
            if c.disclose == Disclosure::Threshold {
                w.push("pub = threshold_disclosure(ask, ok, maxqty, ref_secret)");
                w.push("print_ln('QOMM_DISCLOSE=%s', pub.reveal())");
            }
        }
        Mode::Rfs => {
            w.push(format!("RFS_STEPS = {}", c.rfs_steps));
            w.block(
                r###"
                |# Each step depends on the previous winner's inventory: a genuine serial chain.
                |for step in range(RFS_STEPS):
                |    # the reference moves with the slot, still without revealing the asset
                |    ask, bid, ok, maxqty = quote_layer(inv_state.get_vector(), ref_secret + step, NOW_T)
                |    cost = dir_v.if_else(-bid, ask)
                |    cost = ok.if_else(cost, sint(LARGE))
                |    keys = pack_key(cost, idx.get_vector())
                |    best_key = argmin(keys, M)
                |    best_key.reveal_to(0)
                |    # winner absorbs the flow, so the next quote sees a moved inventory.
                |    # Keys are unique, so matching the key identifies the winner without
                |    # opening the index or paying a secret division.
                |    won = keys == best_key.expand_to_vector(M)
                |    signed_qty = u_dir.if_else(qty_v, -qty_v)
                |    real_v = u_is_real.expand_to_vector(M)
                |    inv_state.assign(inv_state.get_vector() + won * signed_qty * real_v, 0)
                "###,
            );
            if c.public_check {
                w.push("    print_ln('QOMM_RFS_STEP_%s_KEY=%s', step, best_key.reveal())");
            }
            if c.range_query {
                emit_range_query(&mut w);
            }
            if c.disclose == Disclosure::Threshold {
                w.push("pub = threshold_disclosure(ask, ok, maxqty, ref_secret)");
                w.push("print_ln('QOMM_DISCLOSE=%s', pub.reveal())");
            }
        }
    }

    Ok(w.finish())
}

fn emit_range_query(w: &mut Lines) {
    w.block(
        r###"
        |
        |# ---- one range query, named by whoever asked ----
        |#
        |# Nobody publishes a statistic here and nothing decides a
        |# threshold in advance. An asker names a price range and gets
        |# back how many eligible makers quoted inside it, with noise
        |# added outside. A firm contributes 0 or 1 to that count, so the
        |# sensitivity is 1 --- against 300 for the volume fields, which
        |# is why those needed noise of 1200 against a signal of 428.
        |#
        |# The bounds are public: they are what the asker asked. What
        |# they cost is measured --- about 9.6 rounds for the one range,
        |# so 0.14 s on a metro committee and 0.60 s across regions. A
        |# grid of them would be flat in depth only if comparisons
        |# batched, and they do not: 128 ranges is 1,257 rounds. One
        |# range per run is the shape that works, and it is also the
        |# shape that charges the asker for exactly what they asked.
        |Q_LO = sint(QUERY_LO)
        |Q_HI = sint(QUERY_HI)
        |inside = (ask >= Q_LO.expand_to_vector(M)) * \
        |         (ask <= Q_HI.expand_to_vector(M))
        |counted = ok * inside
        |count_a = Array(M, sint)
        |count_a.assign(counted)
        |firms = count_a[0]
        |for i in range(1, M):
        |    firms = firms + count_a[i]
        |print_ln('QOMM_RANGE_COUNT=%s', firms.reveal())
        "###,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lagrange_coefficients_match_consecutive_points() {
        assert_eq!(
            ed25519_lagrange_at_zero(3).unwrap(),
            vec![
                "3",
                "7237005577332262213973186563042994240857116359379907606001950938285454250986",
                "1"
            ]
        );
    }

    #[test]
    fn sentinel_matches_the_packing_rule() {
        assert_eq!(sentinel_for(31, 16, 800_000).unwrap(), 33_554_432);
    }

    #[test]
    fn output_has_one_final_newline() {
        let output = build_program(&ProgramConfig::default()).unwrap();
        assert!(output.ends_with('\n'));
        assert!(!output.ends_with("\n\n"));
    }

    #[test]
    fn complete_quote_program_reads_the_market_time_at_runtime() {
        let config = ProgramConfig {
            persist_wires: true,
            persist_zkpi_wires: true,
            persist_quote_proof_wires: true,
            public_maker_assets: true,
            ..ProgramConfig::default()
        };
        let output = build_program(&config).unwrap();
        assert!(output.contains("from Compiler.library import public_input"));
        assert!(output.contains("NOW_T = public_input()"));
        assert!(!output.contains("NOW_T = 1000"));
    }

    #[test]
    fn persisted_zkpi_widths_are_validated_before_runtime_proof_generation() {
        let production = ProgramConfig {
            persist_wires: true,
            persist_zkpi_wires: true,
            zkpi_amount_bits: PRODUCT_ZKPI_AMOUNT_BITS,
            zkpi_price_bits: PRODUCT_ZKPI_PRICE_BITS,
            ..ProgramConfig::default()
        };
        build_program(&production).unwrap();

        let unsupported = ProgramConfig {
            zkpi_amount_bits: 48,
            ..production
        };
        assert_eq!(
            build_program(&unsupported).unwrap_err().to_string(),
            "zkPI amount and price widths must be one of 8, 16, 32 or 64 bits"
        );
    }

    #[test]
    fn production_dvp_remainder_uses_the_defmi_amount_bound() {
        assert_eq!(
            PRODUCT_DVP_REMAINDER_BITS, PRODUCT_ZKPI_AMOUNT_BITS,
            "the DeFMI verifier applies its amount bound to DvP remainders"
        );
        assert!(is_bulletproof_width(PRODUCT_DVP_REMAINDER_BITS));
    }
}
