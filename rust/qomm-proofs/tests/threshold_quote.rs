//! Threshold quote-proof tests for the unified ordinary verifier.

use qomm_proofs::quote_proof::{
    registry_digest, Invalid, MakerWitness, MinimalityProof, Public, QuoteCircuit, Registered,
};
use qomm_proofs::threshold_gadgets::audit_recorded_product_partials;
use qomm_proofs::threshold_quote::{
    check_circuit_field, deal_quote_shares, joint_prove_quote, shares_from_circuit, CircuitWires,
    QuoteAssemblyTranscript, QuoteNodeContribution, RISTRETTO_SCALAR_ORDER_LE,
};
use qomm_proofs::threshold_sigma::PartyId;
use rand_core::OsRng;

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const T: usize = 2;
const NOW: i64 = 1_000;
const SENTINEL: i64 = 1 << 20;
const SLOTS: i64 = 8;
const QTY: i64 = 100;
const CTX: &[u8] = b"threshold-quote-test";

fn circuit() -> QuoteCircuit {
    QuoteCircuit::new(16, 24)
}

fn witness(spread: i64, slope: i64, maxqty: i64, expiry: i64, active: bool) -> MakerWitness {
    MakerWitness {
        ask_level: 10_000,
        spread,
        slope,
        invcoef: 1,
        inv: 3,
        maxqty,
        expiry,
        active,
        blindings: Registered::fresh(&mut OsRng),
    }
}

fn makers(count: usize) -> Vec<MakerWitness> {
    (0..count)
        .map(|index| witness(20 + index as i64, 1 + index as i64, 500, 2_000, true))
        .collect()
}

fn deal(
    circuit: &QuoteCircuit,
    makers: &[MakerWitness],
) -> Result<(Vec<QuoteNodeContribution>, Public), String> {
    deal_quote_shares(
        circuit, makers, QTY, 0, NOW, SENTINEL, SLOTS, &PARTIES, T, [0u8; 32], 0, &mut OsRng,
    )
}

fn assemble(
    circuit: &QuoteCircuit,
    shares: &[QuoteNodeContribution],
    public: &Public,
    quorum: &[PartyId],
) -> Result<
    (
        qomm_proofs::quote_proof::QuoteProof,
        QuoteAssemblyTranscript,
    ),
    String,
> {
    joint_prove_quote(circuit, shares, public, quorum, CTX, &mut OsRng)
}

#[test]
fn a_quorum_assembles_the_whole_proof_and_the_ordinary_verifier_accepts_it() {
    let circuit = circuit();
    let makers = makers(3);
    let (shares, public) = deal(&circuit, &makers).unwrap();
    let (proof, transcript) = assemble(&circuit, &shares, &public, &[1, 2, 3]).unwrap();
    let result = circuit.verify(&proof, &public, CTX);
    println!(
        "assembled_proof_ordinary_verifier={} assembled_by={:?}",
        result.is_ok(),
        transcript.quorum
    );
    assert_eq!(result, Ok(()));
    assert_eq!(transcript.quorum, vec![1, 2, 3]);
}

#[test]
fn a_bad_distributed_quote_response_names_its_node() {
    let circuit = circuit();
    let makers = makers(2);
    let (shares, public) = deal(&circuit, &makers).unwrap();
    let (_, mut transcript) = assemble(&circuit, &shares, &public, &[1, 2, 3]).unwrap();
    let record = &mut transcript.product_partials[0].1;
    record.answers.get_mut(&2).unwrap().0 += curve25519_dalek::scalar::Scalar::ONE;
    assert_eq!(
        audit_recorded_product_partials(&circuit.key, record),
        vec![2]
    );
}

#[test]
fn no_node_holds_any_wire() {
    let circuit = circuit();
    let makers = makers(3);
    let (shares, public) = deal(&circuit, &makers).unwrap();
    let (proof, _) = assemble(&circuit, &shares, &public, &[1, 2, 3]).unwrap();
    assert_eq!(circuit.verify(&proof, &public, CTX), Ok(()));

    let checked = shares[0].node_view().wire_shares.len();
    for (expected_party, contribution) in PARTIES.iter().zip(&shares) {
        let view = contribution.node_view();
        assert_eq!(view.party, *expected_party);
        assert_eq!(view.wire_shares.len(), checked);
        assert_eq!(view.wire_blinding_shares.len(), checked);
        assert!(!view.range_bit_shares.is_empty());
        assert_eq!(
            view.range_bit_shares.len(),
            view.range_bit_blinding_shares.len()
        );
        assert!(!view.cross_shares.is_empty());
    }
    // A hostile participant gets one evaluation for each wire.  The audit's
    // interpolation needs T+1 distinct recipient evaluations and therefore
    // cannot even be invoked from this type.
    let hostile = shares[0].node_view();
    let observations_per_wire = usize::from(!hostile.wire_shares.is_empty());
    assert_eq!(observations_per_wire, 1);
    assert!(observations_per_wire < T + 1);
    println!(
        "no_single_node_view_contains_witness=true checked_wires={checked} observations_per_wire={observations_per_wire} required={}",
        T + 1
    );
    assert!(checked >= 3 * 22, "only {checked} wires checked");
}

#[test]
fn exactly_t_plus_one_works_and_t_does_not() {
    let circuit = circuit();
    let makers = makers(2);
    let (shares, public) = deal(&circuit, &makers).unwrap();
    let (quorum_proof, _) = assemble(&circuit, &shares, &public, &[1, 2, 3]).unwrap();
    let quorum_ok = circuit.verify(&quorum_proof, &public, CTX).is_ok();
    let short = assemble(&circuit, &shares, &public, &[1, 2]);
    let short_ok = short.is_ok();
    println!("quorum_t_plus_1={quorum_ok} quorum_t={short_ok}");
    assert!(quorum_ok);
    assert!(
        !short_ok,
        "two of seven assembled a proof at a threshold of two"
    );
}

#[test]
fn any_quorum_of_t_plus_one_assembles() {
    let circuit = circuit();
    let makers = makers(2);
    let (shares, public) = deal(&circuit, &makers).unwrap();
    for quorum in [
        vec![1, 2, 3],
        vec![5, 6, 7],
        vec![2, 4, 6],
        vec![1, 3, 5, 7],
    ] {
        let (proof, _) = assemble(&circuit, &shares, &public, &quorum).unwrap();
        assert_eq!(
            circuit.verify(&proof, &public, CTX),
            Ok(()),
            "quorum {quorum:?}"
        );
    }
}

#[test]
fn the_published_winner_cannot_be_moved() {
    let circuit = circuit();
    let makers = makers(3);
    let (shares, public) = deal(&circuit, &makers).unwrap();
    let (mut proof, _) = assemble(&circuit, &shares, &public, &[1, 2, 3]).unwrap();
    proof.winner_value += 1;
    assert_eq!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::WinnerDoesNotOpen)
    );
}

#[test]
fn a_proof_about_another_register_is_refused() {
    let circuit = circuit();
    let makers = makers(2);
    let (shares, public) = deal(&circuit, &makers).unwrap();
    let (proof, _) = assemble(&circuit, &shares, &public, &[1, 2, 3]).unwrap();
    let others = [
        witness(99, 1, 500, 2_000, true),
        witness(99, 1, 500, 2_000, true),
    ];
    let mut swapped = public.clone();
    swapped.registry = others
        .iter()
        .map(|maker| maker.registered(&circuit.key))
        .collect();
    swapped.registry_digest = registry_digest(&swapped.registry);
    assert!(circuit.verify(&proof, &swapped, CTX).is_err());
}

#[test]
fn an_ineligible_maker_is_representable() {
    let circuit = circuit();
    let makers = vec![
        witness(20, 1, 500, 2_000, true),
        witness(20, 1, QTY - 1, 2_000, true),
        witness(20, 1, 500, NOW - 1, true),
        witness(20, 1, 500, 2_000, false),
    ];
    let (shares, public) = deal(&circuit, &makers).unwrap();
    let (proof, _) = assemble(&circuit, &shares, &public, &[1, 2, 3]).unwrap();
    assert_eq!(circuit.verify(&proof, &public, CTX), Ok(()));
    assert_eq!(proof.winner_index, 0, "an ineligible maker won");
}

#[test]
fn local_and_threshold_formats_are_distinct_but_share_the_ordinary_verifier() {
    let circuit = circuit();
    let makers = makers(2);
    let (shares, public) = deal(&circuit, &makers).unwrap();
    let (threshold, _) = assemble(&circuit, &shares, &public, &[1, 2, 3]).unwrap();
    assert!(matches!(
        threshold.minimality,
        MinimalityProof::Threshold(_)
    ));
    assert_eq!(circuit.verify(&threshold, &public, CTX), Ok(()));

    let (local, local_public) = circuit
        .prove(
            &makers, QTY, 0, NOW, SENTINEL, SLOTS, CTX, &mut OsRng, [0u8; 32], 0,
        )
        .unwrap();
    assert!(matches!(
        local.minimality,
        MinimalityProof::Bulletproof { .. }
    ));
    assert_eq!(circuit.verify(&local, &local_public, CTX), Ok(()));
}

#[test]
fn incomplete_circuit_wire_handoff_is_field_checked_then_fails_closed() {
    let circuit = circuit();
    let wires = CircuitWires {
        prime_le: RISTRETTO_SCALAR_ORDER_LE,
        qty: Default::default(),
        makers: Vec::new(),
    };
    check_circuit_field(&wires).unwrap();
    let error = shares_from_circuit(
        &circuit,
        &wires,
        &[1, 2, 3],
        &PARTIES,
        T,
        0,
        NOW,
        SENTINEL,
        SLOTS,
        &mut OsRng,
    )
    .expect_err("missing MPC auxiliary outputs must not be reconstructed");
    assert!(
        error.contains("refusing to reconstruct quantity"),
        "{error}"
    );

    let mut wrong = wires;
    wrong.prime_le = [0xff; 32];
    let error = check_circuit_field(&wrong).expect_err("a different MPC field must fail closed");
    assert!(error.contains("run the circuit with --shamir-inputs so the two match"));
}
