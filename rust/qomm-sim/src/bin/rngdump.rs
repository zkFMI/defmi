//! Print the deterministic simulation stream for contract-vector inspection.
use qomm_sim::deterministic_random::DeterministicRng;

fn main() {
    for seed in [0u64, 1, 20_260_818, 12_345_678_901_234_567_890] {
        let mut r = DeterministicRng::new(seed);
        println!("seed {seed}");
        let randoms: Vec<String> = (0..4).map(|_| format!("{:.17}", r.random())).collect();
        println!("  random    {}", trim(&randoms));
        println!(
            "  getrandbits8 {}",
            (0..4)
                .map(|_| r.getrandbits(8).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!(
            "  getrandbits40 {}",
            (0..3)
                .map(|_| r.getrandbits(40).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!(
            "  randint   {}",
            (0..6)
                .map(|_| r.randint(6, 18).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        let pool = [0, 0, 1, 1, 2];
        println!(
            "  choice    {}",
            (0..6)
                .map(|_| r.choice(&pool).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!(
            "  choices   {}",
            (0..8)
                .map(|_| r.choices(&[0.55, 0.33, 0.12]).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        let g: Vec<String> = (0..5)
            .map(|_| format!("{:.17}", r.gauss(0.0, 6.0)))
            .collect();
        println!("  gauss     {}", trim(&g));
        let p: Vec<String> = (0..3)
            .map(|_| format!("{:.17}", r.paretovariate(1.6)))
            .collect();
        println!("  pareto    {}", trim(&p));
        let u: Vec<String> = (0..3)
            .map(|_| format!("{:.17}", r.uniform(1.5, 4.0)))
            .collect();
        println!("  uniform   {}", trim(&u));
        println!("  sample    {:?}", r.sample(72, 12));
    }
}

/// digits rather than 17 after the point.
fn trim(values: &[String]) -> String {
    values
        .iter()
        .map(|v| {
            let parsed: f64 = v.parse().unwrap();
            let formatted = format!("{parsed:.17e}");
            let _ = formatted;
            format!("{}", Sig17(parsed))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

struct Sig17(f64);

impl std::fmt::Display for Sig17 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = self.0;
        if v == 0.0 {
            return write!(f, "0");
        }
        let exponent = v.abs().log10().floor() as i32;
        let decimals = (16 - exponent).max(0) as usize;
        let text = format!("{v:.decimals$}");
        let text = if text.contains('.') {
            text.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            text
        };
        write!(f, "{text}")
    }
}
