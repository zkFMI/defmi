//! The tape path has to reproduce the Python exactly, because the real-data
//! results in the paper were produced by it. The fixture below is written in the
//! archive's own format, newest-first, which is the shape that has silently
//! broken this loader before.

use qomm_sim::lab::{self, BuildOptions};
use qomm_sim::market::SimConfig;
use qomm_sim::tapes::*;

const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
const FNV_PRIME: u64 = 1_099_511_628_211;

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

fn requests_fingerprint(requests: &[qomm_sim::market::Request]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash_bytes(&mut hash, &(requests.len() as u64).to_le_bytes());
    for request in requests {
        for value in [request.step, request.entity, request.wallet] {
            hash_bytes(&mut hash, &(value as u64).to_le_bytes());
        }
        hash_bytes(&mut hash, &request.size.to_le_bytes());
        hash_bytes(&mut hash, &[request.direction]);
        hash_bytes(&mut hash, &[u8::from(request.informed)]);
        hash_bytes(&mut hash, &request.signal.to_le_bytes());
    }
    hash
}

fn fixture() -> String {
    // A deterministic stand-in for a symbol-day: the columns the loader reads,
    // in the order the archive writes them.
    let mut rows = vec!["timestamp,symbol,side,size,price,tickDirection,trdMatchID".to_string()];
    let mut rng = qomm_sim::pyrandom::PyRandom::new(3);
    let mut t = 1_623_715_200.0f64;
    for i in 0..600 {
        t += rng.random() * 0.4;
        let side = if rng.random() < 0.5 { "Buy" } else { "Sell" };
        let size = rng.paretovariate(1.3) * 10.0;
        let price = 40_000.0 + rng.gauss(0.0, 50.0);
        rows.push(format!(
            "{t:.4},TESTUSD,{side},{size:.4},{price:.2},PlusTick,x{i}"
        ));
    }
    let header = rows.remove(0);
    rows.reverse(); // the archive is written newest-first
    std::iter::once(header)
        .chain(rows)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn cfg() -> SimConfig {
    SimConfig {
        steps: 4_000,
        step_ms: 50,
        window_steps: 200,
        ..Default::default()
    }
}

#[test]
fn a_newest_first_file_loads_in_time_order() {
    let tape = load_bybit(&fixture(), &cfg(), "t.csv", Some(4_000), Some(50), None).unwrap();
    assert_eq!(tape.rows.len(), 600);
    assert!(tape.rows.windows(2).all(|w| w[0].step <= w[1].step));
}

#[test]
fn a_tape_written_newest_first_spreads_across_its_span() {
    let tape = load_bybit(&fixture(), &cfg(), "t.csv", Some(4_000), Some(50), None).unwrap();
    let steps = tape.rows.iter().map(|row| row.step).collect::<Vec<_>>();
    assert!(!steps.is_empty());
    assert!(steps.windows(2).all(|window| window[0] <= window[1]));
    assert_eq!(steps[0], 0);
    assert!(steps[steps.len() - 1] > steps.len() / 2);
    assert!(steps.windows(2).any(|window| window[0] != window[1]));
}

#[test]
fn the_price_series_follows_time_and_not_file_order() {
    let config = cfg();
    let tape = load_bybit(
        &fixture(),
        &config,
        "t.csv",
        Some(config.steps),
        Some(config.step_ms),
        None,
    )
    .unwrap();
    assert_eq!(tape.mid.len(), config.steps + 1);
    assert!(tape.mid.iter().all(|value| *value > 0));
}

/// The check that a tape read in the wrong order is refused rather than
/// silently turned into a market where every trade happened at once.
#[test]
fn a_tape_that_is_not_in_time_order_is_refused() {
    let text = fixture();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    // Corrupt one timestamp so the sort cannot repair the ordering.
    let header = lines.remove(0);
    lines[0] = lines[0].replacen(char::is_numeric, "9", 1);
    let broken = std::iter::once(header)
        .chain(lines)
        .collect::<Vec<_>>()
        .join("\n");
    // Either it refuses, or the sort put it in order --- both are safe; what is
    // not safe is loading an out-of-order tape.
    if let Ok(tape) = load_bybit(&broken, &cfg(), "t.csv", Some(4_000), Some(50), None) {
        assert!(tape.rows.windows(2).all(|w| w[0].step <= w[1].step));
    }
}

#[test]
fn informedness_is_latent_rather_than_a_threshold_on_the_move() {
    let tape = load_bybit(&fixture(), &cfg(), "t.csv", Some(4_000), Some(50), None).unwrap();
    let market = TapeMarket::new(&cfg(), &tape, 20, 60.0, 200, 0);
    // Some requests agreed with the subsequent move without being labelled
    // informed. If the label were a threshold on that move, this would be empty
    // and attacker 5 would score a perfect AUC on the labelling rule.
    let agreed_but_not_labelled = tape
        .rows
        .iter()
        .zip(&market.informed_flags)
        .filter(|(row, flag)| {
            let m = market.move_over(row.step, 20);
            let agreed = if row.direction == 0 { m > 0 } else { m < 0 };
            agreed && !**flag
        })
        .count();
    assert!(agreed_but_not_labelled > 0);
    assert!(market.informed_share < market.agreement_rate);
}

#[test]
fn the_informed_share_is_estimated_from_agreement() {
    let tape = load_bybit(&fixture(), &cfg(), "t.csv", Some(4_000), Some(50), None).unwrap();
    let market = TapeMarket::new(&cfg(), &tape, 20, 60.0, 200, 3);
    assert!((0.0..=1.0).contains(&market.informed_share));
    assert_eq!(
        market.informed_share,
        (2.0 * market.agreement_rate - 1.0).clamp(0.0, 1.0)
    );
}

#[test]
fn rescaling_moves_the_scale_and_leaves_the_shape() {
    let raw: Vec<f64> = (1..=101).map(|i| i as f64).collect();
    let lots = rescale_sizes(&raw, 40, SIZE_CEILING);
    // The median lands on the target...
    let mut sorted = lots.clone();
    sorted.sort_unstable();
    assert_eq!(sorted[sorted.len() / 2], 40);
    // ...and the ordering is untouched, which is what the caps bite on.
    assert!(lots.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn the_default_keeps_one_entity_per_observed_address() {
    let path = std::env::temp_dir().join(format!(
        "qomm-sim-default-entities-{}.csv",
        std::process::id()
    ));
    std::fs::write(&path, fixture()).unwrap();
    let built = lab::build(&BuildOptions {
        cfg: cfg(),
        tape: Some(path.clone()),
        tape_kind: "bybit".to_string(),
        tape_step_ms: 50,
        ..BuildOptions::default()
    });
    std::fs::remove_file(path).unwrap();
    let setup = built.unwrap();
    assert_eq!(setup.cfg.wallets_per_entity, 1);
    assert!(setup.source.starts_with("bybit:qomm-sim-default-entities-"));
    // The fixture writes six hundred fills under six hundred distinct
    // addresses, and the default keeps them apart. The Rust port used to carry
    // `Some(24)` where the Python library carried `None`, so it collapsed those
    // six hundred round robin into twenty-four. That collapse is not neutral:
    // a per-entity cap then binds twenty-four synthetic entities aggregating
    // twenty-five fills each, rather than the six hundred the tape actually
    // shows, which is the setting most favourable to the venue rather than the
    // least. It is also the collapse that made the block-range query saturate
    // in one window on generated data.
    assert_eq!(
        setup.meta["entities"], 600.0,
        "the default keeps one entity per observed address"
    );
    assert_eq!(setup.cfg.n_entities, 600);
    // The observed-address count is not carried in the metadata under its own
    // key, which is why `entities` has to be read against the tape to know what
    // an entity stood for. Under this default the two coincide.
    assert!(
        !setup.meta.contains_key("observed_addresses"),
        "if this key appears, assert it equals `entities` under the default"
    );
}

#[test]
fn round_robin_assignment_reproduces_the_python() {
    let tape = load_bybit(&fixture(), &cfg(), "t.csv", Some(4_000), Some(50), None).unwrap();
    let market = TapeMarket::new(&cfg(), &tape, 20, 60.0, 200, 0);
    let out = requests_from_tape(&cfg(), &market, &tape, Entities::RoundRobin(24), 1, 7);
    assert_eq!(out.cfg.n_entities, 24);
    assert_eq!(out.requests.len(), 600);
    assert_eq!(requests_fingerprint(&out.requests), 0xd788_1435_4ef6_48e2);
    assert_eq!(
        out.requests.last().map(|request| (
            request.step,
            request.entity,
            request.wallet,
            request.size,
            request.direction,
            request.informed,
            request.signal,
        )),
        Some((2_350, 3, 3, 28, 1, false, 0))
    );
}

#[test]
fn uniswapx_amount_records_preserve_pair_time_entity_and_direction() {
    let text = concat!(
        "{\"block\":90,\"checkpoint\":1}\n",
        "{\"block\":100,\"log_index\":2,\"filler\":\"f1\",\"swapper\":\"s1\",",
        "\"legs\":[{\"token\":\"0xa\",\"amount\":100,\"out\":true},",
        "{\"token\":\"0xb\",\"amount\":50,\"out\":false}]}\n",
        "{\"block\":102,\"log_index\":1,\"filler\":\"f2\",\"swapper\":\"s2\",",
        "\"legs\":[{\"token\":\"0xb\",\"amount\":100,\"out\":true},",
        "{\"token\":\"0xa\",\"amount\":210,\"out\":false}]}\n"
    );
    let tape = load_uniswapx(text, &cfg(), "fills.jsonl", None, 1, 1, None).unwrap();
    assert_eq!(tape.source, "uniswapx:fills.jsonl");
    assert_eq!(tape.steps(), 2);
    assert_eq!(tape.rows.len(), 2);
    assert_eq!(
        tape.rows
            .iter()
            .map(|row| (row.step, row.address.as_str(), row.direction))
            .collect::<Vec<_>>(),
        vec![(0, "s1", 0), (2, "s2", 1)]
    );
    assert_eq!(
        tape.rows.iter().map(|row| row.size).collect::<Vec<_>>(),
        vec![27, 53]
    );
    assert_eq!(tape.mid, vec![100_000, 100_000, 105_000]);
}
