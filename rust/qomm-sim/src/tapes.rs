//! Real order flow in place of the generated kind.
//!
//! `market` draws everything: a Gaussian walk, Poisson arrivals, Pareto entity
//! activity. One rejection criterion written down before any measurement was
//! whether the results survive a different data-generating rule, and the honest
//! way to settle that is to stop generating.
//!
//! Two tapes, because no single source carries everything. *UniswapX* is
//! request-for-quote on chain: a fill names the swapper who asked and the filler
//! who won, which is the pair the simulator generates, and the venue is
//! genuinely thin. *Bybit* is a perpetual-futures tape with no identities but
//! the density the simulator assumes and a wide spread in liquidity between
//! symbols.
//!
//! What neither supplies is a maker's pricing rule, so makers stay generated:
//! real policies are unobservable, and they are the design space being swept.

use std::collections::{BTreeMap, VecDeque};

use crate::deterministic_random::DeterministicRng;
use crate::market::{round_half_even, PricePath, Request, SimConfig};

pub const SIZE_CEILING: i64 = 100_000;
pub const SECONDS_PER_BLOCK: usize = 12;

/// One market's history, already on the simulator's step grid.
#[derive(Clone, Debug)]
pub struct Tape {
    /// Reference price per step, in ticks.
    pub mid: Vec<i64>,
    pub rows: Vec<TapeRow>,
    pub source: String,
    pub meta: BTreeMap<String, f64>,
    /// Non-numeric provenance fields kept separate so the simulation core can
    /// continue treating numerical tape metadata uniformly.
    pub meta_text: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct TapeRow {
    pub step: usize,
    pub address: String,
    pub size: i64,
    pub direction: u8,
}

impl Tape {
    pub fn steps(&self) -> usize {
        self.mid.len() - 1
    }
}

/// A market whose price path and informed fraction are measured rather than drawn.
///
/// A tape has no informedness flag --- nothing in a trade record says whether the
/// trader knew something --- so it is estimated, and the estimate stays *latent*.
/// That matters more than it looks: labelling a request informed whenever its
/// signed move cleared a threshold makes the label a deterministic function of
/// exactly the quantity attacker 5 scores on, and that attacker then reports an
/// AUC of 1.0 --- a measurement of the labelling rule, not of the attack. So
/// informedness is assigned by draw among the requests that agreed, at a rate
/// reproducing the estimated share, which is the structure the generated arm has.
pub struct TapeMarket {
    pub cfg: SimConfig,
    pub mid: Vec<i64>,
    pub phi: Vec<f64>,
    pub source: String,
    pub horizon: usize,
    pub agreement_rate: f64,
    pub informed_share: f64,
    pub informed_flags: Vec<bool>,
    pub edge: i64,
    pub measured_phi: Option<f64>,
    pub meta: BTreeMap<String, f64>,
}

impl TapeMarket {
    pub fn new(
        cfg: &SimConfig,
        tape: &Tape,
        horizon: usize,
        edge_percentile: f64,
        phi_window: usize,
        seed: u64,
    ) -> Self {
        let mid = tape.mid.clone();
        let move_over = |step: usize, horizon: usize| -> i64 {
            let end = (step + horizon).min(mid.len() - 1);
            mid[end] - mid[step]
        };
        let mut rng = DeterministicRng::new(seed);

        let agreements: Vec<bool> = tape
            .rows
            .iter()
            .map(|row| {
                let m = move_over(row.step, horizon);
                if row.direction == 0 {
                    m > 0
                } else {
                    m < 0
                }
            })
            .collect();
        let rate = if agreements.is_empty() {
            0.5
        } else {
            agreements.iter().filter(|a| **a).count() as f64 / agreements.len() as f64
        };
        // uninformed flow agrees half the time; the excess is the informed share
        let informed_share = (2.0 * rate - 1.0).clamp(0.0, 1.0);
        let mark = if rate > 0.0 {
            informed_share / rate
        } else {
            0.0
        };

        let mut informed_flags = Vec::with_capacity(tape.rows.len());
        let mut labels: Vec<(usize, bool)> = Vec::with_capacity(tape.rows.len());
        for (row, agreed) in tape.rows.iter().zip(&agreements) {
            let flag = *agreed && rng.random() < mark;
            informed_flags.push(flag);
            labels.push((row.step, flag));
        }

        // Kept for reporting only; the size of a move no longer gates the label.
        let mut moves: Vec<i64> = tape
            .rows
            .iter()
            .map(|r| move_over(r.step, horizon).abs())
            .collect();
        moves.sort_unstable();
        let edge = if moves.is_empty() {
            1
        } else {
            let index =
                ((moves.len() as f64 * edge_percentile / 100.0) as usize).min(moves.len() - 1);
            moves[index].max(1)
        };

        // phi[t] is the share of informed requests in the trailing window, held
        // flat between arrivals because there is nothing to update in between.
        let mut phi = vec![cfg.informed_base; mid.len()];
        let mut recent: VecDeque<bool> = VecDeque::with_capacity(phi_window);
        let mut cursor = 0usize;
        for (step, slot) in phi.iter_mut().enumerate() {
            while cursor < labels.len() && labels[cursor].0 <= step {
                if recent.len() == phi_window {
                    recent.pop_front();
                }
                recent.push_back(labels[cursor].1);
                cursor += 1;
            }
            if !recent.is_empty() {
                *slot = recent.iter().filter(|f| **f).count() as f64 / recent.len() as f64;
            }
        }
        let measured_phi = median(&phi);

        TapeMarket {
            cfg: *cfg,
            mid,
            phi,
            source: tape.source.clone(),
            horizon,
            agreement_rate: rate,
            informed_share,
            informed_flags,
            edge,
            measured_phi,
            meta: tape.meta.clone(),
        }
    }

    pub fn move_over(&self, step: usize, horizon: usize) -> i64 {
        let end = (step + horizon).min(self.mid.len() - 1);
        self.mid[end] - self.mid[step]
    }
}

impl PricePath for TapeMarket {
    fn mid(&self) -> &[i64] {
        &self.mid
    }
}

fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = ordered.len() / 2;
    Some(if ordered.len() % 2 == 1 {
        ordered[mid]
    } else {
        0.5 * (ordered[mid - 1] + ordered[mid])
    })
}

/// Put real sizes on the simulator's lot scale without reshaping them.
///
/// Absolute size is not comparable --- a tape is in tokens or contracts, the
/// simulator in lots --- but the *shape* is what matters, because the entity caps
/// and a maker's `max_qty` bite on the tail. One multiplicative factor fixed by
/// the median moves the distribution onto the right scale and leaves the tail
/// where it is. Anything above the ceiling is clipped, and how often that
/// happens is recorded rather than hidden.
pub fn rescale_sizes(raw: &[f64], target_median: i64, ceiling: i64) -> Vec<i64> {
    let positive: Vec<f64> = raw.iter().copied().filter(|v| *v > 0.0).collect();
    if positive.is_empty() {
        return vec![1; raw.len()];
    }
    let factor = target_median as f64 / median(&positive).unwrap();
    raw.iter()
        .map(|v| round_half_even(v * factor).clamp(1, ceiling))
        .collect()
}

/// What the entity column of a tape means.
///
/// UniswapX carries a real swapper address per request, so PerAddress is the
/// truth there rather than a setting, and it is the least favourable one for
/// the per-entity contribution cap: with one wallet each there is nothing for
/// the cap to collapse.
///
/// A Bybit tape carries no identities at all --- `load_bybit` synthesises
/// `taker:{i}`, one per fill --- so neither variant is measured there.
/// PerAddress asserts that no firm ever trades twice; RoundRobin(n) asserts a
/// firm count and an even split. The default is PerAddress because it is the
/// identity assignment, applying no grouping rather than an invented one, and
/// because the conclusion turns out not to depend on the choice.
///
/// That last clause was measured. On LTCUSDT2021-06-15 at one seed, 411
/// requests, the passive observer's AUC against the baseline protocols rises
/// with the linkage parameter in both settings, slightly faster per address
/// (0.6382 vs 0.6172 at rho=0.25, 0.7886 vs 0.7344 at rho=0.5, 1.0000 at
/// rho=1 either way), while `qomm_rfq` holds at exactly 0.5000 at every rho in
/// both. The paired DP-effect intervals include zero in both settings at six
/// seeds. The ordering that carries the result is the same either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entities {
    /// One entity per observed address, holding one wallet.
    PerAddress,
    /// Observed addresses dealt round-robin into `n` synthetic entities, which
    /// keeps the assignment from smuggling a second generated distribution in
    /// on top of the real arrivals.
    RoundRobin(usize),
}

pub struct TapeRequests {
    pub requests: Vec<Request>,
    pub cfg: SimConfig,
    pub meta: BTreeMap<String, f64>,
    pub entity_kind: &'static str,
}

pub fn requests_from_tape(
    cfg: &SimConfig,
    market: &TapeMarket,
    tape: &Tape,
    entities: Entities,
    wallets_per_entity: usize,
    seed: u64,
) -> TapeRequests {
    let mut rng = DeterministicRng::new(seed);

    let mut order: Vec<&str> = Vec::new();
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    for row in &tape.rows {
        if seen.insert(row.address.as_str(), ()).is_none() {
            order.push(row.address.as_str());
        }
    }

    let (entity_of, n_entities, entity_kind) = match entities {
        Entities::RoundRobin(n) => {
            rng.shuffle(&mut order);
            let map: BTreeMap<&str, usize> =
                order.iter().enumerate().map(|(i, a)| (*a, i % n)).collect();
            (map, n, "assigned round-robin (the tape has no identities)")
        }
        Entities::PerAddress => {
            let map: BTreeMap<&str, usize> =
                order.iter().enumerate().map(|(i, a)| (*a, i)).collect();
            let n = order.len();
            (map, n, "one entity per observed address")
        }
    };

    let requests: Vec<Request> = tape
        .rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let entity = entity_of[row.address.as_str()];
            let wallet = entity * wallets_per_entity
                + if wallets_per_entity > 1 {
                    rng.randrange(0, wallets_per_entity as i64) as usize
                } else {
                    0
                };
            let informed = market.informed_flags[index];
            Request {
                step: row.step,
                entity,
                wallet,
                size: row.size,
                direction: row.direction,
                informed,
                signal: if informed {
                    market.move_over(row.step, market.horizon)
                } else {
                    0
                },
            }
        })
        .collect();

    let out_cfg = SimConfig {
        steps: tape.steps(),
        n_entities,
        wallets_per_entity,
        ..*cfg
    };
    let share =
        requests.iter().filter(|r| r.informed).count() as f64 / requests.len().max(1) as f64;
    let mut meta = tape.meta.clone();
    meta.insert("requests".into(), requests.len() as f64);
    meta.insert("entities".into(), n_entities as f64);
    meta.insert("wallets_per_entity".into(), wallets_per_entity as f64);
    meta.insert("informed_share_measured".into(), share);
    meta.insert("agreement_rate_measured".into(), market.agreement_rate);
    meta.insert("informed_share_estimated".into(), market.informed_share);
    meta.insert("informed_base_assumed".into(), cfg.informed_base);
    meta.insert("edge_ticks_measured".into(), market.edge as f64);
    meta.insert("edge_ticks_assumed".into(), cfg.informed_edge_ticks);

    TapeRequests {
        requests,
        cfg: out_cfg,
        meta,
        entity_kind,
    }
}

#[derive(Clone, Debug)]
struct JsonLeg {
    token: String,
    amount: u128,
    outgoing: bool,
}

#[derive(Clone, Debug)]
struct JsonFill {
    block: usize,
    log_index: usize,
    filler: String,
    swapper: String,
    legs: Vec<JsonLeg>,
}

fn json_field_start<'a>(text: &'a str, key: &str) -> Result<&'a str, String> {
    let needle = format!("\"{key}\"");
    let after_key = text
        .find(&needle)
        .map(|index| &text[index + needle.len()..])
        .ok_or_else(|| format!("missing JSON field '{key}'"))?;
    let colon = after_key
        .find(':')
        .ok_or_else(|| format!("missing ':' after JSON field '{key}'"))?;
    Ok(after_key[colon + 1..].trim_start())
}

/// A JSON integer, saturating at `u128::MAX` and saying when it did.
///
/// an `amount` that is not: the largest is 58 digits, `1.0e57`, against a
/// `u128::MAX` of about `3.4e38`. Those are not trades --- they are a token
/// whose decimals make the number meaningless --- and refusing the whole tape
/// over four of them is worse than reading them as the largest number there is.
///
/// Saturating cannot move the measurement: `rescale_sizes` takes its factor from
/// the *median* of the positive sizes and then clamps to a ceiling, so a value
/// far above the ceiling and a value further above it produce the same lot.
/// That is the argument for saturating rather than failing, and it is why the
/// count is returned rather than swallowed --- an argument that stops being true
/// if the rescaling ever stops being median-based.
fn json_u128_saturating(text: &str, key: &str) -> Result<(u128, bool), String> {
    let value = json_field_start(text, key)?;
    let end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let digits = &value[..end];
    if digits.is_empty() {
        return Err(format!("JSON field '{key}' is not a non-negative integer"));
    }
    match digits.parse::<u128>() {
        Ok(parsed) => Ok((parsed, false)),
        Err(_) => Ok((u128::MAX, true)),
    }
}

fn json_u128(text: &str, key: &str) -> Result<u128, String> {
    json_u128_saturating(text, key).map(|(value, _)| value)
}

fn json_bool(text: &str, key: &str) -> Result<bool, String> {
    let value = json_field_start(text, key)?;
    if value.starts_with("true") {
        Ok(true)
    } else if value.starts_with("false") {
        Ok(false)
    } else {
        Err(format!("JSON field '{key}' is not a boolean"))
    }
}

fn json_string(text: &str, key: &str) -> Result<String, String> {
    let value = json_field_start(text, key)?;
    if !value.starts_with('"') {
        return Err(format!("JSON field '{key}' is not a string"));
    }
    let mut escaped = false;
    let mut out = String::new();
    for character in value[1..].chars() {
        if escaped {
            out.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Ok(out);
        } else {
            out.push(character);
        }
    }
    Err(format!("unterminated JSON string field '{key}'"))
}

fn json_array_objects<'a>(text: &'a str, key: &str) -> Result<Vec<&'a str>, String> {
    let value = json_field_start(text, key)?;
    if !value.starts_with('[') {
        return Err(format!("JSON field '{key}' is not an array"));
    }
    let mut objects = Vec::new();
    let (mut depth, mut start) = (0usize, None);
    let (mut in_string, mut escaped) = (false, false);
    for (index, byte) in value.as_bytes().iter().enumerate().skip(1) {
        let character = *byte as char;
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(index);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    return Err(format!("unbalanced object in JSON field '{key}'"));
                }
                depth -= 1;
                if depth == 0 {
                    objects.push(&value[start.unwrap()..=index]);
                    start = None;
                }
            }
            ']' if depth == 0 => return Ok(objects),
            _ => {}
        }
    }
    Err(format!("unterminated JSON array field '{key}'"))
}

fn readable_legs(fill: &JsonFill) -> Option<(JsonLeg, JsonLeg)> {
    let outgoing = fill
        .legs
        .iter()
        .filter(|leg| leg.outgoing && leg.amount > 0)
        .max_by_key(|leg| leg.amount)?;
    let incoming = fill
        .legs
        .iter()
        .filter(|leg| !leg.outgoing && leg.amount > 0)
        .max_by_key(|leg| leg.amount)?;
    Some((outgoing.clone(), incoming.clone()))
}

fn price_path(
    prices: &[(usize, f64)],
    total_steps: usize,
    cfg: &SimConfig,
    ceiling: i64,
) -> Result<Vec<i64>, String> {
    let mut by_step: BTreeMap<usize, Vec<f64>> = BTreeMap::new();
    for (step, price) in prices {
        by_step.entry(*step).or_default().push(*price);
    }
    let first_step = *by_step.keys().next().ok_or("no prices in selected pair")?;
    let first = median(&by_step[&first_step]).ok_or("no first price")?;
    let mut mid = Vec::with_capacity(total_steps + 1);
    let mut last = cfg.ref_mid0;
    for step in 0..=total_steps {
        if let Some(values) = by_step.get(&step) {
            last = round_half_even(cfg.ref_mid0 as f64 * median(values).unwrap() / first);
        }
        mid.push(last.clamp(1, ceiling));
    }
    Ok(mid)
}

/// UniswapX fill records from the collector's JSON-lines `--amounts` pass.
///
/// The parser is deliberately limited to that published schema, but it still
/// parses fields by name rather than depending on JSON object order.
#[allow(clippy::too_many_arguments)]
pub fn load_uniswapx(
    text: &str,
    cfg: &SimConfig,
    name: &str,
    steps: Option<usize>,
    step_blocks: usize,
    min_requests_per_entity: usize,
    pair: Option<(&str, &str)>,
) -> Result<Tape, String> {
    if step_blocks == 0 {
        return Err("step_blocks must be positive".to_string());
    }
    let mut fills = Vec::new();
    let mut saturated_amounts = 0usize;
    for (line_number, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.contains("\"checkpoint\"") {
            continue;
        }
        let leg_objects = match json_array_objects(line, "legs") {
            Ok(objects) if !objects.is_empty() => objects,
            Ok(_) => continue,
            Err(error) => return Err(format!("{name}: line {}: {error}", line_number + 1)),
        };
        let legs = leg_objects
            .into_iter()
            .map(|object| {
                let (amount, saturated) = json_u128_saturating(object, "amount")?;
                if saturated {
                    saturated_amounts += 1;
                }
                Ok(JsonLeg {
                    token: json_string(object, "token")?,
                    amount,
                    outgoing: json_bool(object, "out")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        fills.push(JsonFill {
            block: json_u128(line, "block")? as usize,
            log_index: json_u128(line, "log_index")? as usize,
            filler: json_string(line, "filler")?,
            swapper: json_string(line, "swapper")?,
            legs,
        });
    }
    if fills.is_empty() {
        return Err(format!(
            "{name} has no fills with decoded legs; run the --amounts pass"
        ));
    }
    fills.sort_by_key(|fill| (fill.block, fill.log_index));

    let mut pair_order: Vec<(String, String)> = Vec::new();
    let mut pair_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for fill in &fills {
        if let Some((sold, bought)) = readable_legs(fill) {
            let key = if sold.token <= bought.token {
                (sold.token, bought.token)
            } else {
                (bought.token, sold.token)
            };
            if !pair_counts.contains_key(&key) {
                pair_order.push(key.clone());
            }
            *pair_counts.entry(key).or_insert(0) += 1;
        }
    }
    if pair_counts.is_empty() {
        return Err(format!("{name} has no fill with both legs readable"));
    }
    let chosen = match pair {
        Some((left, right)) if left == right => {
            return Err(format!("a pair needs two distinct tokens, got {left}"))
        }
        Some((left, right)) if left <= right => (left.to_string(), right.to_string()),
        Some((left, right)) => (right.to_string(), left.to_string()),
        None => {
            let mut ordered = pair_order.into_iter();
            let mut best = ordered.next().unwrap();
            for candidate in ordered {
                if pair_counts[&candidate] > pair_counts[&best] {
                    best = candidate;
                }
            }
            best
        }
    };
    let (quote, base) = (&chosen.0, &chosen.1);

    let kept: Vec<(&JsonFill, JsonLeg, JsonLeg)> = fills
        .iter()
        .filter_map(|fill| {
            let (sold, bought) = readable_legs(fill)?;
            let key = if sold.token <= bought.token {
                (sold.token.clone(), bought.token.clone())
            } else {
                (bought.token.clone(), sold.token.clone())
            };
            (key == chosen).then_some((fill, sold, bought))
        })
        .collect();
    if kept.is_empty() {
        return Err(format!("no fills on the requested pair in {name}"));
    }
    let base_block = kept[0].0.block;
    let span = kept[kept.len() - 1].0.block - base_block;
    let total_steps = steps.unwrap_or_else(|| (span / step_blocks).max(1));

    let mut raw_sizes = Vec::new();
    let mut raw_rows = Vec::new();
    let mut prices = Vec::new();
    for (fill, sold, bought) in kept {
        let step = (fill.block - base_block) / step_blocks;
        if step > total_steps {
            break;
        }
        let base_amount = if sold.token == *base {
            sold.amount
        } else {
            bought.amount
        };
        let quote_amount = if sold.token == *quote {
            sold.amount
        } else {
            bought.amount
        };
        let direction = u8::from(bought.token != *base);
        raw_sizes.push(base_amount as f64);
        prices.push((step, quote_amount as f64 / (base_amount.max(1) as f64)));
        raw_rows.push((step, fill.swapper.clone(), direction, fill.filler.clone()));
    }
    let sizes = rescale_sizes(&raw_sizes, 40, SIZE_CEILING);
    let mid = price_path(&prices, total_steps, cfg, (1 << 20) - 1)?;
    let mut per_entity: BTreeMap<String, usize> = BTreeMap::new();
    let mut winners: BTreeMap<String, usize> = BTreeMap::new();
    for (_, address, _, filler) in &raw_rows {
        *per_entity.entry(address.clone()).or_insert(0) += 1;
        *winners.entry(filler.clone()).or_insert(0) += 1;
    }
    let rows: Vec<TapeRow> = raw_rows
        .into_iter()
        .zip(sizes.iter().copied())
        .filter(|((_, address, _, _), _)| per_entity[address] >= min_requests_per_entity)
        .map(|((step, address, direction, _), size)| TapeRow {
            step,
            address,
            size,
            direction,
        })
        .collect();
    let pair_total: usize = pair_counts.values().sum();
    let meta = [
        ("fills".to_string(), fills.len() as f64),
        ("on_pair".to_string(), pair_counts[&chosen] as f64),
        ("used".to_string(), rows.len() as f64),
        ("pairs_available".to_string(), pair_counts.len() as f64),
        (
            "pair_share".to_string(),
            pair_counts[&chosen] as f64 / pair_total.max(1) as f64,
        ),
        ("blocks".to_string(), span as f64),
        ("step_blocks".to_string(), step_blocks as f64),
        (
            "seconds_per_step".to_string(),
            (step_blocks * SECONDS_PER_BLOCK) as f64,
        ),
        ("distinct_swappers".to_string(), per_entity.len() as f64),
        ("distinct_fillers".to_string(), winners.len() as f64),
        (
            "sizes_at_ceiling".to_string(),
            sizes.iter().filter(|size| **size >= SIZE_CEILING).count() as f64,
        ),
        (
            "sizes_over_largest_bucket".to_string(),
            sizes.iter().filter(|size| **size > 400).count() as f64,
        ),
        // Four of the 150,000 fills carry an `amount` that does not fit in 128
        // read them; this reads them as `u128::MAX`. It is recorded rather than
        // absorbed because the argument that it cannot matter --- the rescaling
        // takes its factor from the median and clamps to a ceiling --- is an
        // argument about today's rescaling, and a reader should be able to see
        // the number the argument is about.
        (
            "amounts_saturated_at_u128".to_string(),
            saturated_amounts as f64,
        ),
    ]
    .into_iter()
    .collect();
    Ok(Tape {
        mid,
        rows,
        source: format!("uniswapx:{name}"),
        meta,
        meta_text: [
            ("pair_quote".to_string(), quote.clone()),
            ("pair_base".to_string(), base.clone()),
        ]
        .into_iter()
        .collect(),
    })
}

/// One symbol-day from the Bybit public trading archive.
///
/// Timestamp resolution changes with the era --- tenths of a millisecond before
/// late 2021 and whole seconds after --- so `step_ms` should be at least a second
/// on the later files, or every trade in a second lands on one step.
pub fn load_bybit(
    text: &str,
    cfg: &SimConfig,
    name: &str,
    steps: Option<usize>,
    step_ms: Option<u64>,
    max_rows: Option<usize>,
) -> Result<Tape, String> {
    load_bybit_slice(text, cfg, name, steps, step_ms, 0, max_rows)
}

#[allow(clippy::too_many_arguments)]
pub fn load_bybit_slice(
    text: &str,
    cfg: &SimConfig,
    name: &str,
    steps: Option<usize>,
    step_ms: Option<u64>,
    start_row: usize,
    max_rows: Option<usize>,
) -> Result<Tape, String> {
    let step_ms = step_ms.unwrap_or(cfg.step_ms);
    let total_steps = steps.unwrap_or(cfg.steps);

    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().ok_or("empty file")?.split(',').collect();
    let column = |name: &str| {
        header
            .iter()
            .position(|h| *h == name)
            .ok_or_else(|| format!("no '{name}' column"))
    };
    let (ts, price_at, size_at, side_at) = (
        column("timestamp")?,
        column("price")?,
        column("size")?,
        column("side")?,
    );

    let mut trades: Vec<(f64, f64, f64, u8)> = Vec::new();
    for (index, line) in lines.enumerate() {
        if index < start_row {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() <= price_at {
            continue;
        }
        trades.push((
            parts[ts].parse().map_err(|_| "bad timestamp")?,
            parts[price_at].parse().map_err(|_| "bad price")?,
            parts[size_at].parse().map_err(|_| "bad size")?,
            // Bybit states the aggressor: a Buy is the taker lifting the offer,
            // which is the simulator's direction 0.
            u8::from(parts[side_at] != "Buy"),
        ));
        if max_rows.is_some_and(|m| trades.len() >= m) {
            break;
        }
    }
    if trades.is_empty() {
        return Err(format!("{name} yielded no trades"));
    }

    // These files are written newest-first. Reading them in file order silently
    // produces negative step indices, so the sort is not optional.
    trades.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    let span_s = total_steps as f64 * step_ms as f64 / 1000.0;
    let base = trades[0].0;
    trades.retain(|t| t.0 - base <= span_s);

    let steps_of: Vec<usize> = trades
        .iter()
        .map(|t| (((t.0 - base) * 1000.0 / step_ms as f64) as usize).min(total_steps))
        .collect();
    // Clamping a negative index to zero would turn a tape read in the wrong
    // order into a tape where every trade happened at once --- which still loads,
    // still runs, and reports a market that never existed.
    if steps_of.first().is_some_and(|s| *s != 0) || steps_of.windows(2).any(|w| w[0] > w[1]) {
        return Err(
            "trades are not in time order after sorting; the tape's own \
                    ordering changed or the sort was lost"
                .into(),
        );
    }

    let prices: Vec<f64> = trades.iter().map(|t| t.1).collect();
    let tick = median(&prices).unwrap() / cfg.ref_mid0 as f64;
    let mut by_step: BTreeMap<usize, Vec<f64>> = BTreeMap::new();
    for (step, price) in steps_of.iter().zip(&prices) {
        by_step.entry(*step).or_default().push(*price);
    }
    let mut mid = Vec::with_capacity(total_steps + 1);
    let mut last = cfg.ref_mid0;
    for step in 0..=total_steps {
        if let Some(values) = by_step.get(&step) {
            last = round_half_even(median(values).unwrap() / tick).max(1);
        }
        mid.push(last);
    }

    let sizes: Vec<f64> = trades.iter().map(|t| t.2).collect();
    let lots = rescale_sizes(&sizes, 40, SIZE_CEILING);
    let rows: Vec<TapeRow> = steps_of
        .iter()
        .zip(&lots)
        .zip(&trades)
        .enumerate()
        .map(|(i, ((step, lot), trade))| TapeRow {
            step: *step,
            address: format!("taker:{i}"),
            size: *lot,
            direction: trade.3,
        })
        .collect();

    let span = trades.last().unwrap().0 - trades[0].0;
    let meta: BTreeMap<String, f64> = [
        ("trades".to_string(), rows.len() as f64),
        ("step_ms".to_string(), step_ms as f64),
        ("span_s".to_string(), span),
        (
            "arrival_per_s".to_string(),
            rows.len() as f64 / span.max(1e-9),
        ),
        ("tick_value".to_string(), tick),
        (
            "sizes_over_largest_bucket".to_string(),
            lots.iter().filter(|v| **v > 400).count() as f64,
        ),
        (
            "sizes_at_ceiling".to_string(),
            lots.iter().filter(|v| **v >= SIZE_CEILING).count() as f64,
        ),
    ]
    .into_iter()
    .collect();

    Ok(Tape {
        mid,
        rows,
        source: format!("bybit:{name}"),
        meta,
        meta_text: BTreeMap::new(),
    })
}
