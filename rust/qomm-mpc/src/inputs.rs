//! Deterministic MP-SPDZ input fixtures and their cleartext reference.
//!
//! `finish_reference`. Reproducibility requires a fixed stream: policies and
//! sharing use separate deterministic MT19937 instances with rejection sampling.

use crate::program::{CheckMode, Mode, Reference, ED25519_ORDER, FIELDS};
use serde_json::Value;
use std::cmp::Ordering;
use std::fmt;

const SLACK_BITS: u32 = 40;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputError(pub String);

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InputError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    values: [i128; FIELDS.len()],
}

impl Policy {
    fn fixture(values: [i128; FIELDS.len()]) -> Self {
        Self { values }
    }

    fn padding() -> Self {
        Self { values: [0; 10] }
    }

    fn get(&self, field: &str) -> i128 {
        self.values[FIELDS
            .iter()
            .position(|candidate| *candidate == field)
            .expect("known policy field")]
    }
}

/// Parse the JSON list accepted by `--policies`.
pub fn parse_policies(text: &str) -> Result<Vec<Policy>, InputError> {
    let value: Value = serde_json::from_str(text).map_err(|error| InputError(error.to_string()))?;
    let entries = value
        .as_array()
        .ok_or_else(|| InputError("--policies must contain a JSON list".into()))?;
    entries
        .iter()
        .map(|entry| {
            let object = entry
                .as_object()
                .ok_or_else(|| InputError("each policy must be a JSON object".into()))?;
            let mut values = [0_i128; FIELDS.len()];
            for (index, field) in FIELDS.iter().enumerate() {
                let value = object
                    .get(*field)
                    .ok_or_else(|| InputError(format!("policy is missing `{field}`")))?;
                values[index] = json_integer(value).ok_or_else(|| {
                    InputError(format!("policy field `{field}` is not an integer"))
                })?;
            }
            Ok(Policy { values })
        })
        .collect()
}

/// Read only the outer list length, matching the CLI's validation order.
///
pub fn policy_count(text: &str) -> Result<usize, InputError> {
    let value: Value = serde_json::from_str(text).map_err(|error| InputError(error.to_string()))?;
    value
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| InputError("--policies must contain a JSON list".into()))
}

fn json_integer(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(value) => Some(i128::from(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(i128::from)
            .or_else(|| value.as_u64().map(i128::from))
            .or_else(|| value.as_f64().map(|number| number.trunc() as i128)),
        Value::String(value) => value.trim().parse().ok(),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct InputConfig<'a> {
    pub n_mm: usize,
    pub n_real_mm: usize,
    pub n_parties: usize,
    pub is_real: i128,
    pub n_requests: usize,
    pub n_assets: usize,
    pub ref_table: &'a [i128],
    pub user_asset: usize,
    pub user_qty: i128,
    pub user_dir: i128,
    pub user_entity: i128,
    pub now_t: i128,
    pub seed: i128,
    pub audit_gates: bool,
    pub value_bits: u32,
    pub field_bits: i128,
    pub use_ref: i128,
    pub reference: Reference,
    pub input_check: bool,
    pub check_mode: CheckMode,
    pub binding_limit: bool,
    pub user_limit: i128,
    /// Pedersen blinding for the Taker's pre-signed limit commitment.  The
    /// production resident path accepts a full scalar field element in the
    /// fixed request frame; this i128 field is retained only for deterministic
    /// fixture generation.
    pub user_limit_blinding: i128,
    /// Pedersen blinding for the quantity commitment already signed in the
    /// Taker mandate. Production accepts the full scalar as a tenth frame
    /// field; deterministic fixtures use this compact value.
    pub user_qty_blinding: i128,
    pub check_coefficients: &'a [i128],
    pub check_repeats: usize,
    pub policies: Option<&'a [Policy]>,
    pub shamir_inputs: bool,
    pub shamir_threshold: usize,
    /// Reservation values already authorized by Maker and Taker.  These are
    /// supplied only when the circuit must emit the DvP proof handoff.  A real
    /// service receives the corresponding per-node shares from admission;
    /// this deterministic generator is the reproducible harness dealer.
    pub dvp: Option<DvpInputs>,
    /// Registered Pedersen blindings for the complete quote proof. Production
    /// nodes receive their Shamir evaluations through encrypted policy state;
    /// this clear fixture is used only to generate reproducible party inputs.
    pub quote_proof: Option<QuoteProofInputs>,
}

pub const QUOTE_POLICY_BLINDING_FIELDS: usize = 9;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuoteProofInputs {
    /// ask_level, spread, slope, invcoef, inv, maxqty, expiry, active, use_ref
    pub maker_policy_blindings: Vec<[i128; QUOTE_POLICY_BLINDING_FIELDS]>,
}

impl QuoteProofInputs {
    pub fn validate(&self, n_mm: usize) -> Result<(), InputError> {
        if self.maker_policy_blindings.len() != n_mm
            || self
                .maker_policy_blindings
                .iter()
                .flatten()
                .any(|value| *value < 0)
        {
            return Err(InputError(
                "quote-proof policy blindings must contain nine non-negative values per padded Maker"
                    .into(),
            ));
        }
        Ok(())
    }

    pub const fn value_count(n_mm: usize) -> usize {
        QUOTE_POLICY_BLINDING_FIELDS * n_mm
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DvpInputs {
    pub taker_securities_reserve: i128,
    pub taker_securities_blinding: i128,
    pub taker_cash_reserve: i128,
    pub taker_cash_blinding: i128,
    pub maker_securities_reserves: Vec<i128>,
    pub maker_securities_blindings: Vec<i128>,
    pub maker_cash_reserves: Vec<i128>,
    pub maker_cash_blindings: Vec<i128>,
    /// Secret scalar behind each Maker's venue-specific settlement handle.
    /// The circuit selects one scalar and proof nodes expose only G*x.
    pub maker_handle_scalars: Vec<i128>,
}

impl DvpInputs {
    pub fn validate(&self, n_mm: usize) -> Result<(), InputError> {
        for (name, values) in [
            ("Maker securities reserves", &self.maker_securities_reserves),
            (
                "Maker securities reserve blindings",
                &self.maker_securities_blindings,
            ),
            ("Maker cash reserves", &self.maker_cash_reserves),
            ("Maker cash reserve blindings", &self.maker_cash_blindings),
            (
                "Maker settlement handle scalars",
                &self.maker_handle_scalars,
            ),
        ] {
            if values.len() != n_mm {
                return Err(InputError(format!(
                    "{name} has {} entries, expected one per padded Maker ({n_mm})",
                    values.len()
                )));
            }
        }
        if [
            self.taker_securities_reserve,
            self.taker_securities_blinding,
            self.taker_cash_reserve,
            self.taker_cash_blinding,
        ]
        .into_iter()
        .chain(self.maker_securities_reserves.iter().copied())
        .chain(self.maker_securities_blindings.iter().copied())
        .chain(self.maker_cash_reserves.iter().copied())
        .chain(self.maker_cash_blindings.iter().copied())
        .chain(self.maker_handle_scalars.iter().copied())
        .any(|value| value < 0)
        {
            return Err(InputError(
                "DvP reserve values and blindings must be non-negative".into(),
            ));
        }
        Ok(())
    }

    pub const fn value_count(n_mm: usize) -> usize {
        4 + 5 * n_mm
    }

    /// Maker-side values that remain in the resident node state. The four
    /// Taker reserve fields are job-specific and travel with the signed RFQ
    /// shares instead of being frozen into a venue-wide state file.
    pub const fn standing_value_count(n_mm: usize) -> usize {
        5 * n_mm
    }
}

#[derive(Clone, Debug)]
pub struct GeneratedInputs {
    per_party: Vec<Vec<BigInt>>,
    reference: ClearReference,
}

impl GeneratedInputs {
    pub fn party_files(&self) -> Vec<String> {
        self.per_party
            .iter()
            .map(|values| {
                let mut text = values
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                text.push('\n');
                text
            })
            .collect()
    }

    pub fn reference_json(&self) -> String {
        self.reference.to_canonical_json()
    }

    pub fn best_price(&self) -> Option<i128> {
        self.reference.best_price
    }

    pub fn best_mm(&self) -> usize {
        self.reference
            .best_mm
            .expect("finish_reference sets best_mm")
    }
}

/// Build deterministic per-party circuit inputs and the clear verification record.
pub fn build_inputs(config: &InputConfig<'_>) -> Result<GeneratedInputs, InputError> {
    let mut rng = DeterministicRng::new(config.seed);
    let mut share_rng = DeterministicRng::new(config.seed ^ 0x5eed);
    let mut per_party = vec![Vec::new(); config.n_parties];
    let prime = config
        .shamir_inputs
        .then(|| BigNat::from_decimal(ED25519_ORDER))
        .transpose()?;

    if prime.is_none() {
        check_field_width(config.n_parties, config.value_bits, config.field_bits)?;
    }

    for _ in 0..config.n_requests {
        for value in [
            config.user_asset as i128,
            config.user_qty,
            config.user_dir,
            config.user_entity,
        ] {
            deal_value(
                config,
                prime.as_ref(),
                &mut share_rng,
                &mut per_party,
                BigInt::from_i128(value),
                None,
            )?;
        }
    }
    deal_value(
        config,
        prime.as_ref(),
        &mut share_rng,
        &mut per_party,
        BigInt::from_i128(config.is_real),
        None,
    )?;

    let mask = share_rng.randrange_power_of_two(config.value_bits);
    deal_value(
        config,
        prime.as_ref(),
        &mut share_rng,
        &mut per_party,
        BigInt::positive(mask.clone()),
        None,
    )?;
    if let Some(dvp) = config.dvp.as_ref() {
        dvp.validate(config.n_mm)?;
        let mut values = vec![
            dvp.taker_securities_reserve,
            dvp.taker_securities_blinding,
            dvp.taker_cash_reserve,
            dvp.taker_cash_blinding,
        ];
        for maker in 0..config.n_mm {
            values.extend([
                dvp.maker_securities_reserves[maker],
                dvp.maker_securities_blindings[maker],
                dvp.maker_cash_reserves[maker],
                dvp.maker_cash_blindings[maker],
                dvp.maker_handle_scalars[maker],
            ]);
        }
        for value in values {
            deal_value(
                config,
                prime.as_ref(),
                &mut share_rng,
                &mut per_party,
                BigInt::from_i128(value),
                None,
            )?;
        }
    }
    if config.binding_limit {
        deal_value(
            config,
            prime.as_ref(),
            &mut share_rng,
            &mut per_party,
            BigInt::from_i128(config.user_limit),
            None,
        )?;
        deal_value(
            config,
            prime.as_ref(),
            &mut share_rng,
            &mut per_party,
            BigInt::from_i128(config.user_limit_blinding),
            None,
        )?;
        let fill_mask = share_rng.randrange_power_of_two(config.value_bits);
        deal_value(
            config,
            prime.as_ref(),
            &mut share_rng,
            &mut per_party,
            BigInt::positive(fill_mask),
            None,
        )?;
        deal_value(
            config,
            prime.as_ref(),
            &mut share_rng,
            &mut per_party,
            BigInt::from_i128(config.user_qty_blinding),
            None,
        )?;
    }

    let mut policies = Vec::with_capacity(config.n_mm);
    for maker in 0..config.n_mm {
        let policy = if maker < config.n_real_mm {
            if let Some(supplied) = config.policies {
                supplied[maker].clone()
            } else {
                Policy::fixture([
                    (maker % config.n_assets) as i128,
                    rng.randint(-15, 15),
                    rng.randint(10, 80),
                    rng.randint(0, 3),
                    rng.randint(0, 2),
                    rng.randint(-50, 50),
                    *rng.choice(&[50_i128, 100, 200, 500]),
                    config.now_t + rng.randint(1, 600),
                    1,
                    config.use_ref,
                ])
            }
        } else {
            Policy::padding()
        };
        for value in policy.values {
            deal_value(
                config,
                prime.as_ref(),
                &mut share_rng,
                &mut per_party,
                BigInt::from_i128(value),
                None,
            )?;
        }
        policies.push(policy);
    }

    if let Some(quote) = config.quote_proof.as_ref() {
        quote.validate(config.n_mm)?;
        for maker in &quote.maker_policy_blindings {
            for value in maker {
                deal_value(
                    config,
                    prime.as_ref(),
                    &mut share_rng,
                    &mut per_party,
                    BigInt::from_i128(*value),
                    None,
                )?;
            }
        }
    }

    if config.input_check {
        if config.check_mode == CheckMode::PerParty {
            check_field_width(config.n_parties, config.value_bits, config.field_bits)?;
            let bits = config
                .field_bits
                .checked_sub(1)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| InputError("field width is outside the supported range".into()))?;
            for values in &mut per_party {
                values.push(BigInt::positive(share_rng.randrange_power_of_two(bits)));
            }
        } else {
            let n_values = config.n_mm * FIELDS.len()
                + config.n_requests * 4
                + 2
                + usize::from(config.binding_limit) * 4
                + config
                    .dvp
                    .as_ref()
                    .map_or(0, |_| DvpInputs::value_count(config.n_mm))
                + config
                    .quote_proof
                    .as_ref()
                    .map_or(0, |_| QuoteProofInputs::value_count(config.n_mm));
            let width = mask_bits_for(n_values, config.value_bits);
            check_field_width(config.n_parties, width, config.field_bits)?;
            for _ in 0..config.check_repeats {
                let check_mask = share_rng.randrange_power_of_two(width);
                deal_value(
                    config,
                    prime.as_ref(),
                    &mut share_rng,
                    &mut per_party,
                    BigInt::positive(check_mask),
                    Some(width),
                )?;
            }
        }
    }

    let reference = cleartext_reference(config, policies, mask)?;
    Ok(GeneratedInputs {
        per_party,
        reference,
    })
}

fn deal_value(
    config: &InputConfig<'_>,
    prime: Option<&BigNat>,
    rng: &mut DeterministicRng,
    per_party: &mut [Vec<BigInt>],
    value: BigInt,
    width: Option<u32>,
) -> Result<(), InputError> {
    let shares = if let Some(prime) = prime {
        shamir_split(
            &value,
            config.n_parties,
            config.shamir_threshold,
            prime,
            rng,
        )?
    } else {
        additive_split(
            &value,
            config.n_parties,
            width.unwrap_or(config.value_bits),
            rng,
        )?
    };
    for (party, share) in shares.into_iter().enumerate() {
        per_party[party].push(share);
    }
    Ok(())
}

/// Complete the clear verification record after the packing sentinel is known.
pub fn finish_reference(
    generated: &mut GeneratedInputs,
    config: &InputConfig<'_>,
    sentinel: i128,
    mode: Mode,
) -> Result<(), InputError> {
    let reference = &mut generated.reference;
    if let (Some(cost), Some(maker)) = (reference.best_cost, reference.best_mm) {
        reference.best_key = Some(checked_key(cost, config.n_mm, maker)?);
    }
    if let (Some(ask), Some(ask_mm), Some(bid), Some(bid_mm)) = (
        reference.best_ask,
        reference.best_ask_mm,
        reference.best_bid,
        reference.best_bid_mm,
    ) {
        reference.ask_key = Some(checked_key(ask, config.n_mm, ask_mm)?);
        reference.bid_key = Some(checked_key(-bid, config.n_mm, bid_mm)?);
    }
    if reference.best_cost.is_none() {
        reference.no_eligible_maker = true;
        reference.best_cost = Some(sentinel);
        reference.best_mm = Some(0);
        reference.best_key = Some(
            sentinel
                .checked_mul(config.n_mm as i128)
                .ok_or_else(|| InputError("reference key overflow".into()))?,
        );
    }
    if reference.best_ask.is_none() {
        reference.best_ask = Some(sentinel);
        reference.best_ask_mm = Some(0);
        reference.ask_key = Some(
            sentinel
                .checked_mul(config.n_mm as i128)
                .ok_or_else(|| InputError("reference ask key overflow".into()))?,
        );
        reference.best_bid = Some(-sentinel);
        reference.best_bid_mm = Some(0);
        reference.bid_key = reference.ask_key;
    }
    reference.is_real = config.is_real;
    reference.n_assets = config.n_assets;
    reference.ref_table = config.ref_table.to_vec();
    reference.user_asset = config.user_asset;
    reference.padded_mm = config.n_mm;
    reference.real_mm = config.n_real_mm;
    reference.mode = mode.as_str();
    Ok(())
}

fn checked_key(cost: i128, padded: usize, maker: usize) -> Result<i128, InputError> {
    cost.checked_mul(padded as i128)
        .and_then(|value| value.checked_add(maker as i128))
        .ok_or_else(|| InputError("reference key overflow".into()))
}

fn cleartext_reference(
    config: &InputConfig<'_>,
    policies: Vec<Policy>,
    mask: BigNat,
) -> Result<ClearReference, InputError> {
    let mut best_cost = None;
    let mut best_mm = None;
    let mut best_ask = None;
    let mut best_bid = None;
    let mut best_ask_mm = None;
    let mut best_bid_mm = None;
    let mut quotes = Vec::with_capacity(policies.len());

    for (maker, policy) in policies.iter().enumerate() {
        let skew = policy
            .get("invcoef")
            .checked_mul(policy.get("inv"))
            .ok_or_else(|| InputError("reference skew overflow".into()))?;
        let depth = policy
            .get("slope")
            .checked_mul(config.user_qty)
            .ok_or_else(|| InputError("reference depth overflow".into()))?;
        let anchor = if config.reference == Reference::None {
            policy.get("ask_level")
        } else {
            policy
                .get("use_ref")
                .checked_mul(config.ref_table[config.user_asset])
                .and_then(|value| value.checked_add(policy.get("ask_level")))
                .ok_or_else(|| InputError("reference anchor overflow".into()))?
        };
        let ask = anchor
            .checked_add(depth)
            .and_then(|value| value.checked_add(skew))
            .ok_or_else(|| InputError("reference ask overflow".into()))?;
        let bid = anchor
            .checked_sub(policy.get("spread"))
            .and_then(|value| value.checked_sub(depth))
            .and_then(|value| value.checked_add(skew))
            .ok_or_else(|| InputError("reference bid overflow".into()))?;
        let mut eligible = policy.get("asset") == config.user_asset as i128
            && config.user_qty <= policy.get("maxqty")
            && policy.get("active") == 1;
        if !config.audit_gates {
            eligible &= policy.get("expiry") > config.now_t;
        }
        quotes.push(Quote {
            mm: maker,
            ask,
            bid,
            eligible,
        });
        if !eligible {
            continue;
        }
        if best_ask.is_none_or(|current| ask < current) {
            best_ask = Some(ask);
            best_ask_mm = Some(maker);
        }
        if best_bid.is_none_or(|current| bid > current) {
            best_bid = Some(bid);
            best_bid_mm = Some(maker);
        }
        let cost = if config.user_dir == 1 { -bid } else { ask };
        if best_cost.is_none_or(|current| cost < current) {
            best_cost = Some(cost);
            best_mm = Some(maker);
        }
    }

    let best_price = best_cost.map(|cost| if config.user_dir == 1 { -cost } else { cost });
    let eligible_count = quotes.iter().filter(|quote| quote.eligible).count();
    Ok(ClearReference {
        ask_key: None,
        best_ask,
        best_ask_mm,
        best_bid,
        best_bid_mm,
        best_cost,
        best_key: None,
        best_mm,
        best_price,
        bid_key: None,
        eligible_count,
        is_real: 0,
        mask,
        mode: "",
        n_assets: 0,
        no_eligible_maker: best_cost.is_none(),
        padded_mm: 0,
        quotes,
        real_mm: 0,
        ref_table: Vec::new(),
        user_asset: 0,
    })
}

fn mask_bits_for(n_values: usize, value_bits: u32) -> u32 {
    value_bits + 6 + usize_bit_length(n_values.saturating_sub(1)) + 35
}

fn check_field_width(n_nodes: usize, value_bits: u32, field_bits: i128) -> Result<(), InputError> {
    let needed = value_bits + SLACK_BITS + usize_bit_length(n_nodes.saturating_sub(1)) + 2;
    if field_bits < i128::from(needed) {
        return Err(InputError(format!(
            "a {field_bits}-bit field cannot hold {n_nodes} shares of a {value_bits}-bit value: {needed} bits are needed. Widen the field or lower the slack, and say which in the artifact."
        )));
    }
    Ok(())
}

fn usize_bit_length(value: usize) -> u32 {
    usize::BITS - value.leading_zeros()
}

fn additive_split(
    value: &BigInt,
    n_nodes: usize,
    value_bits: u32,
    rng: &mut DeterministicRng,
) -> Result<Vec<BigInt>, InputError> {
    if n_nodes < 2 {
        return Err(InputError("sharing needs at least two nodes".into()));
    }
    if value.bit_len() > value_bits {
        return Err(InputError(format!(
            "value needs {} bits, declared {value_bits}",
            value.bit_len()
        )));
    }
    let share_bits = value_bits
        .checked_add(SLACK_BITS)
        .ok_or_else(|| InputError("share width overflow".into()))?;
    let mut shares = Vec::with_capacity(n_nodes);
    let mut sum = BigNat::zero();
    for _ in 0..n_nodes - 1 {
        let share = rng.randrange_power_of_two(share_bits);
        sum.add_assign(&share);
        shares.push(BigInt::positive(share));
    }
    shares.push(value.subtract_nat(&sum));
    Ok(shares)
}

fn shamir_split(
    value: &BigInt,
    n_nodes: usize,
    threshold: usize,
    prime: &BigNat,
    rng: &mut DeterministicRng,
) -> Result<Vec<BigInt>, InputError> {
    if n_nodes < threshold.saturating_mul(2).saturating_add(1) {
        return Err(InputError(format!(
            "{n_nodes} nodes cannot carry a threshold of {threshold}"
        )));
    }
    let mut coefficients = Vec::with_capacity(threshold + 1);
    coefficients.push(value.modulo(prime));
    for _ in 0..threshold {
        coefficients.push(rng.below_big(prime));
    }
    let mut shares = Vec::with_capacity(n_nodes);
    for x in 1..=n_nodes {
        let mut accumulator = BigNat::zero();
        for coefficient in coefficients.iter().rev() {
            accumulator = accumulator.mul_small_add_mod(x, coefficient, prime);
        }
        shares.push(BigInt::positive(accumulator));
    }
    Ok(shares)
}

#[derive(Clone, Debug)]
struct Quote {
    mm: usize,
    ask: i128,
    bid: i128,
    eligible: bool,
}

#[derive(Clone, Debug)]
struct ClearReference {
    ask_key: Option<i128>,
    best_ask: Option<i128>,
    best_ask_mm: Option<usize>,
    best_bid: Option<i128>,
    best_bid_mm: Option<usize>,
    best_cost: Option<i128>,
    best_key: Option<i128>,
    best_mm: Option<usize>,
    best_price: Option<i128>,
    bid_key: Option<i128>,
    eligible_count: usize,
    is_real: i128,
    mask: BigNat,
    mode: &'static str,
    n_assets: usize,
    no_eligible_maker: bool,
    padded_mm: usize,
    quotes: Vec<Quote>,
    real_mm: usize,
    ref_table: Vec<i128>,
    user_asset: usize,
}

impl ClearReference {
    fn to_canonical_json(&self) -> String {
        let mut out = String::from("{\n");
        json_line(&mut out, 1, "ask_key", option_integer(self.ask_key), true);
        json_line(&mut out, 1, "best_ask", option_integer(self.best_ask), true);
        json_line(
            &mut out,
            1,
            "best_ask_mm",
            option_usize(self.best_ask_mm),
            true,
        );
        json_line(&mut out, 1, "best_bid", option_integer(self.best_bid), true);
        json_line(
            &mut out,
            1,
            "best_bid_mm",
            option_usize(self.best_bid_mm),
            true,
        );
        json_line(
            &mut out,
            1,
            "best_cost",
            option_integer(self.best_cost),
            true,
        );
        json_line(&mut out, 1, "best_key", option_integer(self.best_key), true);
        json_line(&mut out, 1, "best_mm", option_usize(self.best_mm), true);
        json_line(
            &mut out,
            1,
            "best_price",
            option_integer(self.best_price),
            true,
        );
        json_line(&mut out, 1, "bid_key", option_integer(self.bid_key), true);
        json_line(
            &mut out,
            1,
            "eligible_count",
            self.eligible_count.to_string(),
            true,
        );
        json_line(&mut out, 1, "is_real", self.is_real.to_string(), true);
        json_line(&mut out, 1, "mask", self.mask.to_string(), true);
        json_line(&mut out, 1, "mode", format!("\"{}\"", self.mode), true);
        json_line(&mut out, 1, "n_assets", self.n_assets.to_string(), true);
        json_line(
            &mut out,
            1,
            "no_eligible_maker",
            json_bool(self.no_eligible_maker).into(),
            true,
        );
        json_line(&mut out, 1, "padded_mm", self.padded_mm.to_string(), true);
        out.push_str("  \"quotes\": [\n");
        for (index, quote) in self.quotes.iter().enumerate() {
            out.push_str("    {\n");
            json_line(&mut out, 3, "ask", quote.ask.to_string(), true);
            json_line(&mut out, 3, "bid", quote.bid.to_string(), true);
            json_line(
                &mut out,
                3,
                "eligible",
                json_bool(quote.eligible).into(),
                true,
            );
            json_line(&mut out, 3, "mm", quote.mm.to_string(), false);
            out.push_str("    }");
            if index + 1 != self.quotes.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ],\n");
        json_line(&mut out, 1, "real_mm", self.real_mm.to_string(), true);
        out.push_str("  \"ref_table\": [\n");
        for (index, value) in self.ref_table.iter().enumerate() {
            out.push_str("    ");
            out.push_str(&value.to_string());
            if index + 1 != self.ref_table.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ],\n");
        json_line(
            &mut out,
            1,
            "user_asset",
            self.user_asset.to_string(),
            false,
        );
        out.push_str("}\n");
        out
    }
}

fn json_line(out: &mut String, indent: usize, key: &str, value: String, comma: bool) {
    out.push_str(&"  ".repeat(indent));
    out.push('"');
    out.push_str(key);
    out.push_str("\": ");
    out.push_str(&value);
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn option_integer(value: Option<i128>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn option_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn json_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BigInt {
    negative: bool,
    magnitude: BigNat,
}

impl BigInt {
    fn from_i128(value: i128) -> Self {
        Self {
            negative: value < 0,
            magnitude: BigNat::from_u128(value.unsigned_abs()),
        }
        .normalized()
    }

    fn positive(magnitude: BigNat) -> Self {
        Self {
            negative: false,
            magnitude,
        }
    }

    fn normalized(mut self) -> Self {
        if self.magnitude.is_zero() {
            self.negative = false;
        }
        self
    }

    fn bit_len(&self) -> u32 {
        self.magnitude.bit_len()
    }

    fn subtract_nat(&self, rhs: &BigNat) -> Self {
        if self.negative {
            let mut magnitude = self.magnitude.clone();
            magnitude.add_assign(rhs);
            return Self {
                negative: true,
                magnitude,
            }
            .normalized();
        }
        match self.magnitude.cmp(rhs) {
            Ordering::Greater | Ordering::Equal => Self {
                negative: false,
                magnitude: self.magnitude.sub(rhs),
            },
            Ordering::Less => Self {
                negative: true,
                magnitude: rhs.sub(&self.magnitude),
            },
        }
        .normalized()
    }

    fn modulo(&self, modulus: &BigNat) -> BigNat {
        debug_assert!(self.magnitude < *modulus);
        if self.negative && !self.magnitude.is_zero() {
            modulus.sub(&self.magnitude)
        } else {
            self.magnitude.clone()
        }
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        write!(f, "{}", self.magnitude)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BigNat {
    /// Little-endian base-2^32 limbs.
    limbs: Vec<u32>,
}

impl Ord for BigNat {
    fn cmp(&self, other: &Self) -> Ordering {
        self.limbs
            .len()
            .cmp(&other.limbs.len())
            .then_with(|| self.limbs.iter().rev().cmp(other.limbs.iter().rev()))
    }
}

impl PartialOrd for BigNat {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BigNat {
    fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    fn from_u128(mut value: u128) -> Self {
        let mut limbs = Vec::new();
        while value != 0 {
            limbs.push(value as u32);
            value >>= 32;
        }
        Self { limbs }
    }

    fn from_decimal(value: &str) -> Result<Self, InputError> {
        let mut out = Self::zero();
        for byte in value.bytes() {
            if !byte.is_ascii_digit() {
                return Err(InputError(format!("invalid decimal integer `{value}`")));
            }
            out.mul_small_assign(10);
            out.add_small_assign(u32::from(byte - b'0'));
        }
        Ok(out)
    }

    fn power_of_two(bit: u32) -> Self {
        let mut limbs = vec![0; bit as usize / 32 + 1];
        limbs[bit as usize / 32] = 1 << (bit % 32);
        Self { limbs }
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    fn bit_len(&self) -> u32 {
        self.limbs.last().map_or(0, |last| {
            (self.limbs.len() as u32 - 1) * 32 + (32 - last.leading_zeros())
        })
    }

    fn add_assign(&mut self, rhs: &Self) {
        let len = self.limbs.len().max(rhs.limbs.len());
        self.limbs.resize(len, 0);
        let mut carry = 0_u64;
        for index in 0..len {
            let sum = u64::from(self.limbs[index])
                + u64::from(*rhs.limbs.get(index).unwrap_or(&0))
                + carry;
            self.limbs[index] = sum as u32;
            carry = sum >> 32;
        }
        if carry != 0 {
            self.limbs.push(carry as u32);
        }
    }

    fn add_small_assign(&mut self, rhs: u32) {
        let mut carry = u64::from(rhs);
        let mut index = 0;
        while carry != 0 {
            if index == self.limbs.len() {
                self.limbs.push(0);
            }
            let sum = u64::from(self.limbs[index]) + carry;
            self.limbs[index] = sum as u32;
            carry = sum >> 32;
            index += 1;
        }
    }

    fn sub(&self, rhs: &Self) -> Self {
        debug_assert!(self >= rhs);
        let mut out = self.clone();
        let mut borrow = 0_i64;
        for index in 0..out.limbs.len() {
            let value = i64::from(out.limbs[index])
                - i64::from(*rhs.limbs.get(index).unwrap_or(&0))
                - borrow;
            if value < 0 {
                out.limbs[index] = (value + (1_i64 << 32)) as u32;
                borrow = 1;
            } else {
                out.limbs[index] = value as u32;
                borrow = 0;
            }
        }
        debug_assert_eq!(borrow, 0);
        out.normalize();
        out
    }

    fn mul_small_assign(&mut self, rhs: usize) {
        if rhs == 0 || self.is_zero() {
            self.limbs.clear();
            return;
        }
        let mut carry = 0_u128;
        for limb in &mut self.limbs {
            let product = u128::from(*limb) * rhs as u128 + carry;
            *limb = product as u32;
            carry = product >> 32;
        }
        while carry != 0 {
            self.limbs.push(carry as u32);
            carry >>= 32;
        }
    }

    fn mul_small_add_mod(&self, rhs: usize, addend: &Self, modulus: &Self) -> Self {
        let mut out = self.clone();
        out.mul_small_assign(rhs);
        out.add_assign(addend);
        while out >= *modulus {
            out = out.sub(modulus);
        }
        out
    }

    fn div_rem_small(&mut self, divisor: u32) -> u32 {
        let mut remainder = 0_u64;
        for limb in self.limbs.iter_mut().rev() {
            let value = (remainder << 32) | u64::from(*limb);
            *limb = (value / u64::from(divisor)) as u32;
            remainder = value % u64::from(divisor);
        }
        self.normalize();
        remainder as u32
    }
}

impl fmt::Display for BigNat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return f.write_str("0");
        }
        let mut value = self.clone();
        let mut chunks = Vec::new();
        while !value.is_zero() {
            chunks.push(value.div_rem_small(1_000_000_000));
        }
        write!(f, "{}", chunks.pop().expect("nonzero has a chunk"))?;
        for chunk in chunks.iter().rev() {
            write!(f, "{chunk:09}")?;
        }
        Ok(())
    }
}

const MT_N: usize = 624;
const MT_M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7fff_ffff;

struct DeterministicRng {
    state: [u32; MT_N],
    index: usize,
}

impl DeterministicRng {
    fn new(seed: i128) -> Self {
        let mut key = Vec::new();
        let mut value = seed.unsigned_abs();
        if value == 0 {
            key.push(0);
        }
        while value != 0 {
            key.push(value as u32);
            value >>= 32;
        }
        let mut rng = Self {
            state: [0; MT_N],
            index: MT_N + 1,
        };
        rng.init_by_array(&key);
        rng
    }

    fn init_genrand(&mut self, seed: u32) {
        self.state[0] = seed;
        for index in 1..MT_N {
            let previous = self.state[index - 1];
            self.state[index] = 1_812_433_253_u32
                .wrapping_mul(previous ^ (previous >> 30))
                .wrapping_add(index as u32);
        }
        self.index = MT_N;
    }

    fn init_by_array(&mut self, key: &[u32]) {
        self.init_genrand(19_650_218);
        let mut i = 1_usize;
        let mut j = 0_usize;
        let mut count = MT_N.max(key.len());
        while count != 0 {
            let previous = self.state[i - 1];
            self.state[i] = (self.state[i] ^ (previous ^ (previous >> 30)).wrapping_mul(1_664_525))
                .wrapping_add(key[j])
                .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= MT_N {
                self.state[0] = self.state[MT_N - 1];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
            count -= 1;
        }
        count = MT_N - 1;
        while count != 0 {
            let previous = self.state[i - 1];
            self.state[i] = (self.state[i]
                ^ (previous ^ (previous >> 30)).wrapping_mul(1_566_083_941))
            .wrapping_sub(i as u32);
            i += 1;
            if i >= MT_N {
                self.state[0] = self.state[MT_N - 1];
                i = 1;
            }
            count -= 1;
        }
        self.state[0] = 0x8000_0000;
    }

    fn next_u32(&mut self) -> u32 {
        if self.index >= MT_N {
            for index in 0..MT_N {
                let y = (self.state[index] & UPPER_MASK)
                    | (self.state[(index + 1) % MT_N] & LOWER_MASK);
                let mut next = self.state[(index + MT_M) % MT_N] ^ (y >> 1);
                if y & 1 != 0 {
                    next ^= MATRIX_A;
                }
                self.state[index] = next;
            }
            self.index = 0;
        }
        let mut value = self.state[self.index];
        self.index += 1;
        value ^= value >> 11;
        value ^= (value << 7) & 0x9d2c_5680;
        value ^= (value << 15) & 0xefc6_0000;
        value ^= value >> 18;
        value
    }

    fn getrandbits(&mut self, bits: u32) -> BigNat {
        if bits == 0 {
            return BigNat::zero();
        }
        let mut limbs = Vec::with_capacity(bits.div_ceil(32) as usize);
        let mut remaining = bits;
        while remaining != 0 {
            let take = remaining.min(32);
            let word = if take == 32 {
                self.next_u32()
            } else {
                self.next_u32() >> (32 - take)
            };
            limbs.push(word);
            remaining -= take;
        }
        let mut value = BigNat { limbs };
        value.normalize();
        value
    }

    fn below_big(&mut self, bound: &BigNat) -> BigNat {
        let bits = bound.bit_len();
        loop {
            let value = self.getrandbits(bits);
            if value < *bound {
                return value;
            }
        }
    }

    fn below_u64(&mut self, bound: u64) -> u64 {
        let big = self.below_big(&BigNat::from_u128(u128::from(bound)));
        big.limbs
            .iter()
            .rev()
            .fold(0_u64, |value, limb| (value << 32) | u64::from(*limb))
    }

    fn randrange_power_of_two(&mut self, bits: u32) -> BigNat {
        self.below_big(&BigNat::power_of_two(bits))
    }

    fn randint(&mut self, start: i128, end: i128) -> i128 {
        start + i128::from(self.below_u64((end - start + 1) as u64))
    }

    fn choice<'a, T>(&mut self, choices: &'a [T]) -> &'a T {
        &choices[self.below_u64(choices.len() as u64) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_random_integer_stream_matches_known_values() {
        let mut rng = DeterministicRng::new(7);
        assert_eq!(rng.randint(-15, 15), -5);
        assert_eq!(rng.randint(10, 80), 29);
        assert_eq!(rng.randint(0, 3), 3);
    }

    #[test]
    fn ed25519_order_round_trips_decimal() {
        assert_eq!(
            BigNat::from_decimal(ED25519_ORDER).unwrap().to_string(),
            ED25519_ORDER
        );
    }
}
