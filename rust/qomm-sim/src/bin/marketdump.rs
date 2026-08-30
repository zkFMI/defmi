use qomm_sim::market::*;

fn main() {
    let cfg = SimConfig {
        steps: 4_000,
        ..Default::default()
    };
    let m = ReferenceMarket::new(&cfg, cfg.seed);
    let mms = build_market_makers(&cfg, cfg.seed + 1);
    let reqs = build_requests(&cfg, &m, cfg.seed + 2);

    println!(
        "mid {}",
        m.mid[..8]
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!(
        "phi {}",
        m.phi[..5]
            .iter()
            .map(|v| sig15(*v))
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("makers");
    for mm in mms.iter().take(5) {
        println!(
            "  {} {} {} {} {} {} {}",
            mm.mm_id,
            mm.base_half,
            mm.slope,
            mm.inv_coef,
            mm.max_qty,
            sig15(mm.kappa),
            mm.inv_limit
        );
    }
    println!("requests {}", reqs.len());
    for r in reqs.iter().take(6) {
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
    let (ask, bid) = mms[0].quote(100_000, 100, 0.3);
    println!("quote ({ask}, {bid}) {}", mms[0].half_spread(0.3, 100));
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
