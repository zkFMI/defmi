use qomm_mpc::program::{build_program, ProgramConfig};

fn emit(binding_limit: bool, argmin_arity: usize) -> String {
    build_program(&ProgramConfig {
        n_mm: 16,
        n_parties: 7,
        binding_limit,
        argmin_arity,
        ..ProgramConfig::default()
    })
    .unwrap()
}

fn argmin_fill_body(source: &str) -> &str {
    source
        .split_once("def argmin_fill")
        .unwrap()
        .1
        .split_once("\ndef ")
        .unwrap()
        .0
}

#[test]
fn the_standalone_comparison_after_the_tournament_is_gone() {
    let source = emit(true, 2);
    assert!(source.contains("argmin_fill"));
    assert!(!source.contains("fill = (best_key <= limit_key)"));
}

#[test]
fn the_last_level_compares_three_pairs_where_it_compared_one() {
    let source = emit(true, 2);
    let body = argmin_fill_body(&source);
    assert!(body.matches("<=").count() >= 1);
    assert!(body.contains("left.get_vector() <= right.get_vector()"));
    assert!(body.contains("while size > 2:"));
    let last = body.split_once("bits.assign(").unwrap().1;
    assert_eq!(last.matches("if_else").count(), 2);
}

#[test]
fn the_kary_tournament_folds_too() {
    let source = emit(true, 4);
    assert!(source.contains("def kary_level("));
    assert!(source.contains("while size > arity:"));
    let body = argmin_fill_body(&source);
    assert!(body.contains("finalists[p] if p != q else limit"));
}

#[test]
fn nothing_is_emitted_when_there_is_no_limit() {
    let source = emit(false, 2);
    assert!(!source.contains("argmin_fill"));
    assert!(!source.contains("limit_key"));
}

#[test]
fn request_batch_size_never_changes_the_packed_price_scale() {
    let source = build_program(&ProgramConfig {
        n_mm: 16,
        n_requests: 4,
        binding_limit: true,
        ..ProgramConfig::default()
    })
    .unwrap();
    assert!(source.contains("return cost * M + index_vec"));
    assert!(source.contains("limit_key = u_limit * M + (M - 1)"));
    assert!(!source.contains("limit_key = u_limit * WIDE"));
}
