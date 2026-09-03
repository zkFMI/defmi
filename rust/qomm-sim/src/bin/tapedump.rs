use qomm_sim::market::SimConfig;
use qomm_sim::tapes::*;

fn main() {
    let cfg = SimConfig {
        steps: 4_000,
        step_ms: 50,
        window_steps: 200,
        ..Default::default()
    };
    let text = std::fs::read_to_string("/tmp/testtape.csv").unwrap();
    let tape = load_bybit(&text, &cfg, "testtape.csv", Some(4_000), Some(50), None).unwrap();
    println!("rows {} steps {}", tape.rows.len(), tape.steps());
    println!("mid[:6] {:?}", &tape.mid[..6]);
    let meta: Vec<String> = tape
        .meta
        .iter()
        .map(|(k, v)| format!("'{k}': {}", sig(*v)))
        .collect();
    println!("meta {{{}}}", meta.join(", "));

    let market = TapeMarket::new(&cfg, &tape, 20, 60.0, 200, 0);
    println!(
        "agreement {} informed {} edge {} phi_med {}",
        sig15(market.agreement_rate),
        sig15(market.informed_share),
        market.edge,
        sig15(market.measured_phi.unwrap())
    );

    let out = requests_from_tape(&cfg, &market, &tape, Entities::RoundRobin(24), 1, 7);
    println!(
        "requests {} entities {}",
        out.requests.len(),
        out.cfg.n_entities
    );
    for r in out.requests.iter().take(5) {
        println!(
            "  {} {} {} {} {} {} {}",
            r.step,
            r.entity,
            r.wallet,
            r.size,
            r.direction,
            u8::from(r.informed),
            r.signal
        );
    }
    println!(
        "informed_share_measured {}",
        sig15(out.meta["informed_share_measured"])
    );
}

fn sig(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    let rounded = (v * 1e9).round() / 1e9;
    let text = format!("{rounded}");
    text
}

fn sig15(v: f64) -> String {
    if v == 0.0 {
        return "0".into();
    }
    let exponent = v.abs().log10().floor() as i32;
    let decimals = (14 - exponent).max(0) as usize;
    let text = format!("{v:.decimals$}");
    if text.contains('.') {
        text.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        text
    }
}
