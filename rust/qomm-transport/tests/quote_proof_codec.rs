use qomm_proofs::quote_proof::{MakerWitness, QuoteCircuit, Registered};
use qomm_proofs::threshold_quote::{deal_quote_shares, joint_prove_quote};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_transport::proof_codec::{
    decode_quote_verification, encode_quote_verification, QuoteVerificationBundle,
};
use rand_core::OsRng;

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const CONTEXT: [u8; 32] = [0x51; 32];

fn makers() -> Vec<MakerWitness> {
    (0..3)
        .map(|index| MakerWitness {
            ask_level: 10_000 + index,
            spread: 20 + index,
            slope: 1 + index,
            invcoef: 1,
            inv: 3,
            maxqty: 500,
            expiry: 2_000,
            active: true,
            blindings: Registered::fresh(&mut OsRng),
        })
        .collect()
}

#[test]
fn threshold_quote_round_trips_and_is_reverified() {
    let circuit = QuoteCircuit::new(16, 24);
    let makers = makers();
    let (shares, public) = deal_quote_shares(
        &circuit,
        &makers,
        100,
        0,
        1_000,
        1 << 20,
        8,
        &PARTIES,
        2,
        [0x61; 32],
        7,
        &mut OsRng,
    )
    .unwrap();
    let (proof, _) =
        joint_prove_quote(&circuit, &shares, &public, &[1, 4, 7], &CONTEXT, &mut OsRng).unwrap();
    let bundle = QuoteVerificationBundle {
        context: CONTEXT,
        eligibility_bits: 16,
        span_bits: 24,
        public,
        proof,
    };
    let expected = bundle.verify().unwrap();
    let encoded = encode_quote_verification(&bundle).unwrap();
    let decoded = decode_quote_verification(&encoded).unwrap();
    assert_eq!(decoded.verify().unwrap(), expected);

    let mut tampered = encoded;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(decode_quote_verification(&tampered).is_err());
}

#[test]
fn local_single_prover_quote_is_not_valid_settlement_evidence() {
    let circuit = QuoteCircuit::new(16, 24);
    let makers = makers();
    let (proof, public) = circuit
        .prove(
            &makers,
            100,
            0,
            1_000,
            1 << 20,
            8,
            &CONTEXT,
            &mut OsRng,
            [0x61; 32],
            7,
        )
        .unwrap();
    let bundle = QuoteVerificationBundle {
        context: CONTEXT,
        eligibility_bits: 16,
        span_bits: 24,
        public,
        proof,
    };
    assert!(encode_quote_verification(&bundle)
        .unwrap_err()
        .contains("single-prover"));
}
