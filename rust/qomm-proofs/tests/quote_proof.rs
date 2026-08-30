//! The proof has to accept the true winner and reject every way of claiming a
//! different one. Minimality is the property under test: membership alone would
//! let a prover open any key it liked.

use curve25519_dalek::scalar::Scalar;
use qomm_proofs::quote_proof::{
    registered_policy_digest, registry_digest, Invalid, MakerWitness, MinimalityProof,
    QuoteCircuit, Registered,
};
use rand_core::OsRng;

fn makers() -> Vec<MakerWitness> {
    // Full spreads are doubled while the converted ask levels preserve prices.
    [(8i64, 16i64), (5, 10), (12, 24)]
        .iter()
        .enumerate()
        .map(|(i, (ask_level, spread))| MakerWitness {
            ask_level: *ask_level,
            spread: *spread,
            slope: 1 + i as i64,
            invcoef: 1,
            inv: 10 * (i as i64 + 1),
            maxqty: 1_000,
            expiry: 10_000,
            active: true,
            // registered before the request: the proof is about these, not about
            // whatever the prover would otherwise commit to at proving time
            blindings: Registered::fresh(&mut OsRng),
        })
        .collect()
}

const CTX: &[u8] = b"test";

#[test]
fn maker_mandate_digest_binds_both_the_slot_and_every_registered_policy_field() {
    let circuit = QuoteCircuit::default();
    let registered = makers()
        .into_iter()
        .map(|maker| maker.registered(&circuit.key))
        .collect::<Vec<_>>();

    let original = registered_policy_digest(0, &registered[0]);
    assert_ne!(original, registered_policy_digest(1, &registered[0]));

    let mut substituted = registered[0];
    substituted.maxqty = registered[1].maxqty;
    assert_ne!(original, registered_policy_digest(0, &substituted));
}

#[test]
fn the_true_winner_verifies_and_is_the_tightest() {
    let circuit = QuoteCircuit::default();
    let (proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .expect("honest makers prove");
    assert_eq!(circuit.verify(&proof, &public, CTX), Ok(()));
    // packed key = effective * n_slots + index, so the index rides in the low bits
    assert_eq!(proof.winner_value as usize % 4, proof.winner_index);
    // The tightest spread and lowest base ask do not win by themselves: cost
    // carries the depth term too, and maker 0's shallower slope beats maker 1
    // at this size. Asserting the winner rather than the spread is the point.
    assert_eq!(proof.winner_index, 0);
}

#[test]
fn claiming_a_loser_as_the_winner_fails_minimality() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .expect("honest makers prove");
    proof.winner_index = 2;
    assert!(matches!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::WinnerDoesNotOpen) | Err(Invalid::NotMinimal)
    ));
}

/// The gap this test exists for was real: an opening proof shows knowledge of
/// *some* opening, so binding the commitment alone leaves the published price a
/// free parameter and a venue can quote whatever it likes.
#[test]
fn a_tampered_winner_value_does_not_open() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .expect("honest makers prove");
    proof.winner_value += 1;
    assert_eq!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::WinnerDoesNotOpen)
    );
}

#[test]
fn a_proof_does_not_carry_across_contexts() {
    let circuit = QuoteCircuit::default();
    let (proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .expect("honest makers prove");
    assert!(circuit.verify(&proof, &public, b"another venue").is_err());
}

#[test]
fn the_direction_changes_who_wins() {
    let circuit = QuoteCircuit::default();
    let mut ms = makers();
    // Spread does not move maker 0's ask, but its whole 400 ticks move the bid.
    // That makes maker 0 the best ask and maker 1 the best bid.
    ms[0].spread = 400;
    let (ask, ask_public) = circuit
        .prove(
            &ms,
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    let (bid, bid_public) = circuit
        .prove(
            &ms,
            100,
            1,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    assert_eq!(circuit.verify(&ask, &ask_public, CTX), Ok(()));
    assert_eq!(circuit.verify(&bid, &bid_public, CTX), Ok(()));
    // qty=100 gives asks [118, 225, 342] and bids [-482, -185, -282].
    // The published value packs `(cost + sentinel) * 4 + slot`; sell cost is
    // -bid. The public offset permits the normal positive-bid case as well.
    assert_eq!(
        (ask.winner_index, ask.winner_value),
        (0, ((1 << 20) + 118) * 4)
    );
    assert_eq!(
        (bid.winner_index, bid.winner_value),
        (1, ((1 << 20) + 185) * 4 + 1)
    );
}

#[test]
fn an_ineligible_maker_appears_and_cannot_win() {
    // It used to be refused outright: a negative margin has no range proof, so
    // the only way to serve the request was to gate the maker out before
    // proving -- omission by another name, which the register cannot see.
    let circuit = QuoteCircuit::default();
    let mut ms = makers();
    ms[0].maxqty = 10; // smaller than the request
    let (proof, public) = circuit
        .prove(
            &ms,
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    assert_eq!(circuit.verify(&proof, &public, CTX), Ok(()));
    assert_ne!(proof.winner_index, 0, "a maker over its size limit won");
}

/// The forgery the conjunction closes: switch off the maker that would win.
#[test]
fn an_eligible_maker_cannot_be_switched_off() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    let winner = proof.winner_index;
    proof.maker_proofs[winner].commitments.ok = circuit
        .key
        .commit(&Scalar::ZERO, &Scalar::random(&mut OsRng));
    assert_eq!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::Eligibility(winner))
    );
}

/// A maker's commitment swapped for another's is caught by the register now,
/// not by the product proof further down. That is the stronger refusal: the
/// product only says the arithmetic is consistent, and the register says whose
/// arithmetic it was supposed to be.
#[test]
fn a_swapped_maker_commitment_is_not_on_the_register() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    let other = proof.maker_proofs[1].commitments.slope;
    proof.maker_proofs[0].commitments.slope = other;
    assert_eq!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::NotOnTheRegister(0, "slope"))
    );
}

/// The statement is what says whose policies these are. Without a register
/// behind it the proof establishes a minimum over numbers the prover chose.
#[test]
fn a_register_that_does_not_match_the_proof_is_refused() {
    let circuit = QuoteCircuit::default();
    let (proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();

    let mut short = public.clone();
    short.registry.pop();
    assert_eq!(
        circuit.verify(&proof, &short, CTX),
        Err(Invalid::RegistrySize)
    );

    let mut relabelled = public.clone();
    relabelled.registry_digest = [0u8; 32];
    assert_eq!(
        circuit.verify(&proof, &relabelled, CTX),
        Err(Invalid::RegistryDigest)
    );

    let mut rewritten = public.clone();
    rewritten.registry[0].slope = rewritten.registry[1].slope;
    rewritten.registry_digest = qomm_proofs::quote_proof::registry_digest(&rewritten.registry);
    assert_eq!(
        circuit.verify(&proof, &rewritten, CTX),
        Err(Invalid::NotOnTheRegister(0, "slope"))
    );
}

#[test]
fn a_witness_with_no_registered_blindings_cannot_prove() {
    let circuit = QuoteCircuit::default();
    let mut ms = makers();
    ms[0].blindings = Registered::default();
    assert!(circuit
        .prove(
            &ms,
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0
        )
        .is_err());
}

#[test]
fn the_eligibility_aggregate_must_cover_the_stated_margins() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    let key = &circuit.key;
    proof.maker_proofs[0].commitments.fits =
        key.commit(&Scalar::from(999u64), &Scalar::random(&mut OsRng));
    // The size test is derived from the register and the request, so a
    // commitment the prover picked is not on the register.
    assert_eq!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::NotOnTheRegister(0, "maxqty"))
    );
}

#[test]
fn every_registered_price_field_is_bound_to_the_quote() {
    let circuit = QuoteCircuit::default();
    let (proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();

    // These fields must remain tied to the registered commitments even after
    // recomputing the registry digest.
    let mut rewritten = public.clone();
    rewritten.registry[0].ask_level = circuit
        .key
        .commit(&Scalar::from(1u64), &Scalar::random(&mut OsRng));
    rewritten.registry_digest = qomm_proofs::quote_proof::registry_digest(&rewritten.registry);
    assert!(circuit.verify(&proof, &rewritten, CTX).is_err());

    let mut rewritten = public.clone();
    rewritten.registry[0].spread = circuit
        .key
        .commit(&Scalar::from(2u64), &Scalar::random(&mut OsRng));
    rewritten.registry_digest = qomm_proofs::quote_proof::registry_digest(&rewritten.registry);
    assert!(circuit.verify(&proof, &rewritten, CTX).is_err());
}

#[test]
fn cost_and_packed_key_are_derived_not_prover_chosen() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    proof.maker_proofs[0].commitments.cost += circuit.key.g;
    assert_eq!(circuit.verify(&proof, &public, CTX), Err(Invalid::Cost(0)));

    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    proof.key_commitments[0] += circuit.key.g;
    assert_eq!(circuit.verify(&proof, &public, CTX), Err(Invalid::Key(0)));
}

#[test]
fn complete_public_statement_is_transcript_bound() {
    let circuit = QuoteCircuit::default();
    let (proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [7u8; 32],
            19,
        )
        .unwrap();

    let mut moved = public.clone();
    moved.direction = 1;
    assert!(circuit.verify(&proof, &moved, CTX).is_err());
    let mut moved = public.clone();
    moved.market_digest = [8u8; 32];
    assert!(circuit.verify(&proof, &moved, CTX).is_err());
    let mut moved = public.clone();
    moved.slot += 1;
    assert!(circuit.verify(&proof, &moved, CTX).is_err());
}

#[test]
fn malformed_shapes_are_rejected_without_panicking() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    proof.winner_index = usize::MAX;
    assert!(matches!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::Malformed(_))
    ));

    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    proof.key_commitments.pop();
    assert!(matches!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::Malformed(_))
    ));
}

#[test]
fn a_proof_about_no_makers_is_not_a_proof() {
    let circuit = QuoteCircuit::default();
    let (proof, mut public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    assert_eq!(circuit.verify(&proof, &public, CTX), Ok(()));
    public.registry.clear();
    public.registry_digest = registry_digest(&public.registry);
    assert_eq!(circuit.verify(&proof, &public, CTX), Err(Invalid::NoMakers));
}

#[test]
fn minimality_cannot_be_deleted() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .unwrap();
    assert_eq!(circuit.verify(&proof, &public, CTX), Ok(()));
    proof.minimality = MinimalityProof::Threshold(Vec::new());
    assert_eq!(
        circuit.verify(&proof, &public, CTX),
        Err(Invalid::Malformed(
            "one minimality proof is required per maker"
        ))
    );
}

#[test]
fn invalid_configuration_and_arithmetic_fail_closed() {
    assert!(QuoteCircuit::try_new(63, 32).is_err());
    assert!(QuoteCircuit::try_new(32, 65).is_err());
    let circuit = QuoteCircuit::default();
    assert!(circuit
        .prove(
            &makers(),
            100,
            2,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .is_err());
    assert!(circuit
        .prove(
            &makers(),
            100,
            0,
            1_000,
            1 << 20,
            2,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .is_err());
    let mut overflowing = makers();
    overflowing[0].slope = i64::MAX;
    assert!(circuit
        .prove(
            &overflowing,
            2,
            0,
            1_000,
            1 << 20,
            4,
            CTX,
            &mut OsRng,
            [0u8; 32],
            0,
        )
        .is_err());
}
