use qomm_mpc::inputs::{build_inputs, DvpInputs, InputConfig};
use qomm_mpc::program::{build_program, CheckMode, ProgramConfig, Reference};

#[test]
fn generated_circuit_persists_the_complete_dvp_witness_after_the_zkpi_witness() {
    let source = build_program(&ProgramConfig {
        n_mm: 4,
        n_parties: 7,
        persist_wires: true,
        persist_zkpi_wires: true,
        persist_dvp_wires: true,
        zkpi_amount_bits: 16,
        zkpi_price_bits: 32,
        dvp_remainder_bits: 32,
        ..ProgramConfig::default()
    })
    .unwrap();
    for required in [
        "dvp_cash = W_qty[0] * zkpi_price",
        "dvp_product_cross = dvp_cash_blinding - zkpi_qty_blinding * zkpi_price",
        "selected_maker_securities_reserve = winner_flags[0]",
        "selected_maker_cash_reserve = winner_flags[0]",
        "dvp_direction = req_dir[0]",
        "dvp_securities_reserve = dvp_direction.if_else(dvp_taker_securities_reserve,",
        // The Taker's cash reserve is the priced amount when the Taker buys and
        // its signed cash reserve when it sells; the Maker's side is carried as
        // its own pool-before opening (V8, see program_parity.rs).
        "dvp_cash_reserve = dvp_direction.if_else(dvp_cash,",
        "dvp_securities_remainder = dvp_securities_reserve - W_qty[0]",
        "dvp_cash_remainder = dvp_cash_reserve - dvp_cash",
        "dvp_maker_pool_before = dvp_direction.if_else(selected_maker_cash_reserve,",
        "dvp_maker_delivery = dvp_direction.if_else(dvp_cash, W_qty[0])",
        "dvp_maker_pool_remainder = dvp_maker_pool_before - dvp_maker_delivery",
        "dvp_securities_remainder.bit_decompose(DVP_REMAINDER_BITS)",
        "dvp_cash_remainder.bit_decompose(DVP_REMAINDER_BITS)",
        "dvp_maker_pool_remainder.bit_decompose(DVP_REMAINDER_BITS)",
        "wires += [dvp_cash, dvp_cash_blinding,",
        "wires += [dvp_maker_pool_remainder, dvp_maker_pool_remainder_blinding]",
    ] {
        assert!(
            source.contains(required),
            "missing generated line: {required}\n--- generated DvP block ---\n{}",
            source
                .lines()
                .filter(|line| line.contains("dvp_") || line.contains("selected_maker"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    assert!(
        source.find("zkpi_price_bit_cross").unwrap()
            < source
                .find("wires += [dvp_cash, dvp_cash_blinding,")
                .unwrap()
    );
}

fn input_config(dvp: Option<DvpInputs>) -> InputConfig<'static> {
    InputConfig {
        n_mm: 4,
        n_real_mm: 4,
        n_parties: 7,
        is_real: 1,
        n_requests: 1,
        n_assets: 1,
        ref_table: &[100_000],
        user_asset: 0,
        user_qty: 10,
        user_dir: 0,
        user_entity: 42,
        now_t: 1_000,
        seed: 7,
        audit_gates: false,
        value_bits: 64,
        field_bits: 253,
        use_ref: 1,
        reference: Reference::Anchored,
        input_check: false,
        check_mode: CheckMode::PerParty,
        binding_limit: false,
        user_limit: 100_000,
        user_limit_blinding: 1,
        user_qty_blinding: 1,
        response_mask: None,
        fill_mask: None,
        check_coefficients: &[],
        check_repeats: 7,
        policies: None,
        shamir_inputs: true,
        shamir_threshold: 2,
        dvp,
        quote_proof: None,
    }
}

#[test]
fn reserve_openings_are_shamir_shared_for_both_directions_and_every_maker() {
    let without = build_inputs(&input_config(None)).unwrap().party_files();
    let with = build_inputs(&input_config(Some(DvpInputs {
        taker_securities_reserve: 20,
        taker_securities_blinding: 11,
        taker_cash_reserve: 2_000_000,
        taker_cash_blinding: 13,
        maker_securities_reserves: vec![20, 21, 22, 23],
        maker_securities_blindings: vec![17, 19, 23, 29],
        maker_cash_reserves: vec![2_000_000; 4],
        maker_cash_blindings: vec![31, 37, 41, 43],
        maker_handle_scalars: vec![21, 22, 23, 24],
    })))
    .unwrap()
    .party_files();
    for (without, with) in without.iter().zip(&with) {
        assert_eq!(
            with.split_whitespace().count(),
            without.split_whitespace().count() + DvpInputs::value_count(4)
        );
    }
}

#[test]
fn negative_reservation_inputs_fail_closed() {
    let error = build_inputs(&input_config(Some(DvpInputs {
        taker_securities_reserve: -1,
        taker_securities_blinding: 11,
        taker_cash_reserve: 2_000_000,
        taker_cash_blinding: 13,
        maker_securities_reserves: vec![20; 4],
        maker_securities_blindings: vec![17; 4],
        maker_cash_reserves: vec![2_000_000; 4],
        maker_cash_blindings: vec![19; 4],
        maker_handle_scalars: vec![21, 22, 23, 24],
    })))
    .unwrap_err();
    assert!(error.to_string().contains("must be non-negative"));
}
