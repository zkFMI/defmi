use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::liquidity::{
    deal_liquidity_shares, joint_prove_liquidity, verify_liquidity, LiquidityProof, LiquidityShares,
};
use qomm_zk::pedersen::Pedersen;
use rand_core::OsRng;

const PARTIES: [usize; 7] = [1, 2, 3, 4, 5, 6, 7];
const QUORUM: [usize; 3] = [1, 2, 3];
const THRESHOLD: usize = 2;
const QUOTE: [u8; 32] = [0x51; 32];

fn prove(
    key: &Pedersen,
    eligible: &[u8],
    minimum: usize,
    quorum: &[usize],
) -> Result<(LiquidityShares, LiquidityProof, Vec<RistrettoPoint>), String> {
    let shares = deal_liquidity_shares(key, eligible, minimum, &PARTIES, THRESHOLD, &mut OsRng)?;
    let commitments = shares
        .eligibility
        .iter()
        .map(|wire| wire.commitment)
        .collect();
    let proof = joint_prove_liquidity(key, &shares, quorum, minimum, QUOTE, &mut OsRng)?;
    Ok((shares, proof, commitments))
}

#[test]
fn threshold_proof_verifies_without_disclosing_exact_count() {
    let key = Pedersen::new(b"qomm:liquidity:v1");
    let (shares, proof, commitments) = prove(&key, &[1, 0, 1, 1, 0, 1, 1], 3, &QUORUM).unwrap();
    assert!(verify_liquidity(&key, &proof, &commitments, &QUOTE));
    for party in PARTIES {
        let visible = shares
            .eligibility
            .iter()
            .fold(Scalar::ZERO, |sum, wire| sum + wire.value[&party]);
        assert_ne!(visible, Scalar::from(5_u64));
    }
}

#[test]
fn false_threshold_has_no_proof() {
    let key = Pedersen::new(b"qomm:liquidity:v1");
    let error =
        deal_liquidity_shares(&key, &[1, 0, 0, 1], 3, &PARTIES, THRESHOLD, &mut OsRng).unwrap_err();
    assert_eq!(
        error,
        "fewer makers are eligible than the claimed threshold"
    );
}

#[test]
fn quote_commitments_and_statement_digest_are_bound() {
    let key = Pedersen::new(b"qomm:liquidity:v1");
    let (_, proof, commitments) = prove(&key, &[1, 1, 1, 0], 3, &QUORUM).unwrap();
    assert!(verify_liquidity(&key, &proof, &commitments, &QUOTE));
    let mut moved = commitments.clone();
    moved[0] = key.commit(&Scalar::ONE, &Scalar::random(&mut OsRng));
    assert!(!verify_liquidity(&key, &proof, &moved, &QUOTE));
    assert!(!verify_liquidity(&key, &proof, &commitments, &[0x52; 32]));
}

#[test]
fn fewer_than_a_quorum_cannot_assemble() {
    let key = Pedersen::new(b"qomm:liquidity:v1");
    let error = prove(&key, &[1, 1, 1, 0], 3, &[1, 2]).err().unwrap();
    assert!(error.contains("cannot define degree 2"));
}

#[test]
fn count_commitment_cannot_be_replaced() {
    let key = Pedersen::new(b"qomm:liquidity:v1");
    let (_, mut proof, commitments) = prove(&key, &[1, 1, 1, 0], 3, &QUORUM).unwrap();
    assert!(verify_liquidity(&key, &proof, &commitments, &QUOTE));
    proof.count_commitment = key.commit(&Scalar::from(4_u64), &Scalar::random(&mut OsRng));
    assert!(!verify_liquidity(&key, &proof, &commitments, &QUOTE));
}
