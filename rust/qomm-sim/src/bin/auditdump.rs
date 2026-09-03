use qomm_sim::audit::clopper_pearson;

fn main() {
    for (k, n) in [
        (0usize, 100usize),
        (5, 100),
        (50, 100),
        (95, 100),
        (100, 100),
        (12, 4_000),
    ] {
        let (lo, hi) = clopper_pearson(k, n, 0.05);
        println!("CP {k}/{n}: {lo:.12} {hi:.12}");
    }
    for (a, b, x) in [
        (2.0, 3.0, 0.4),
        (0.5, 0.5, 0.25),
        (10.0, 20.0, 0.3),
        (1.0, 4_000.0, 0.001),
    ] {
        println!(
            "betainc({a},{b},{x}) = {:.14}",
            qomm_sim::audit::betainc_public(a, b, x)
        );
    }
}
