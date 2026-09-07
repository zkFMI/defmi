//! Adversarial verifier regressions. These invoke actual proof construction and
//! verification, not a stubbed accept/reject result.

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_defmi::notes::{NoteLedger, Opening, Wallet};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::sigma::{prove_opening, verify_linear};
use rand_core::OsRng;

fn funded() -> (NoteLedger, Wallet, Pedersen, Opening) {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let mut ledger = NoteLedger::new(key.clone(), 32);
    let owner = Wallet::new(&mut rng);
    let blind = Scalar::random(&mut rng);
    let note = ledger
        .build_note(
            &owner.address,
            1000,
            key.commit_u64(1000, &blind),
            &blind,
            &mut rng,
        )
        .expect("valid fixture note encryption");
    ledger.add(note);
    let opening = ledger.scan(&owner, &key)[0].1;
    (ledger, owner, key, opening)
}

#[test]
fn native_security_regression_serial_shift_cannot_inflate_a_note() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let mut ledger = NoteLedger::new(key.clone(), 32);
    let owner = Wallet::new(&mut rng);
    for _ in 0..8 {
        let blind = Scalar::random(&mut rng);
        let note = ledger
            .build_note(
                &owner.address,
                1000,
                key.commit_u64(1000, &blind),
                &blind,
                &mut rng,
            )
            .expect("valid fixture note encryption");
        ledger.add(note);
    }
    let (index, opening) = ledger.scan(&owner, &key)[0];
    let forged = Opening {
        value: 2000,
        serial: opening.serial - Scalar::from(1000u64),
        blinding: opening.blinding,
    };
    let ring = (0..8).collect::<Vec<_>>();
    let attempt = ledger.build_spend(
        &ring,
        index,
        &forged,
        &key.g,
        &Scalar::ZERO,
        &[(owner.address, 2000)],
        b"native-security",
        &mut rng,
    );
    if let Ok(spend) = attempt {
        assert!(
            ledger
                .check_spend(&ring, &spend.proof, b"native-security", &mut rng)
                .is_err(),
            "verifier accepted twice the actual input value under a changed serial"
        );
    }
}

#[test]
fn native_security_regression_nullifier_does_not_identify_the_public_input_key() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let mut ledger = NoteLedger::new(key.clone(), 32);
    let owner = Wallet::new(&mut rng);
    for _ in 0..8 {
        let blind = Scalar::random(&mut rng);
        let note = ledger
            .build_note(
                &owner.address,
                1000,
                key.commit_u64(1000, &blind),
                &blind,
                &mut rng,
            )
            .expect("valid fixture note encryption");
        ledger.add(note);
    }
    let (index, opening) = ledger.scan(&owner, &key)[0];
    let spend = ledger
        .build_spend(
            &(0..8).collect::<Vec<_>>(),
            index,
            &opening,
            &key.g,
            &Scalar::ZERO,
            &[(owner.address, 1000)],
            b"native-security",
            &mut rng,
        )
        .unwrap();
    assert_ne!(
        spend.proof.serial_point, ledger.notes[index].one_time,
        "public nullifier directly identifies the spent note"
    );
}

#[test]
fn native_security_regression_linear_check_enforces_the_claimed_constant() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let blind = Scalar::random(&mut rng);
    let commitment = key.commit_u64(1, &blind);
    // This is a valid proof of an opening to ONE, not a proof that the linear
    // residual is ZERO. The relation verifier must reject it.
    let forged = prove_opening(
        &key,
        &mut Transcript::new(b"linear-security"),
        &commitment,
        &Scalar::ONE,
        &blind,
        &mut rng,
    );
    assert!(!verify_linear(
        &key,
        &mut Transcript::new(b"linear-security"),
        &[commitment],
        &[Scalar::ONE],
        &Scalar::ZERO,
        &forged
    ));
}

#[test]
fn native_security_regression_new_destinations_cannot_change_the_nullifier() {
    let (mut ledger, owner, key, opening) = funded();
    let first = ledger
        .build_spend(
            &[0],
            0,
            &opening,
            &key.g,
            &Scalar::ZERO,
            &[(owner.address, 1000)],
            b"first",
            &mut OsRng,
        )
        .unwrap();
    let other = Wallet::new(&mut OsRng);
    let second = ledger
        .build_spend(
            &[0],
            0,
            &opening,
            &key.g,
            &Scalar::ZERO,
            &[(other.address, 1000)],
            b"second",
            &mut OsRng,
        )
        .unwrap();
    ledger
        .check_spend(&[0], &first.proof, b"first", &mut OsRng)
        .unwrap();
    ledger
        .check_spend(&[0], &second.proof, b"second", &mut OsRng)
        .unwrap();
    assert_eq!(first.proof.serial_point, second.proof.serial_point);
    ledger.apply_spend(&first.proof, first.notes).unwrap();
    assert!(ledger.is_spent(&opening.serial));
    assert_eq!(
        ledger.check_spend(&[0], &second.proof, b"second", &mut OsRng),
        Err("serial already spent")
    );
}

#[test]
fn native_security_regression_destination_swap_is_rejected_without_state_change() {
    let (mut ledger, owner, key, opening) = funded();
    let spend = ledger
        .build_spend(
            &[0],
            0,
            &opening,
            &key.g,
            &Scalar::ZERO,
            &[(owner.address, 1000)],
            b"destination",
            &mut OsRng,
        )
        .unwrap();
    ledger
        .check_spend(&[0], &spend.proof, b"destination", &mut OsRng)
        .unwrap();
    let mut changed = spend.notes.clone();
    changed[0].one_time = Wallet::new(&mut OsRng).address.spend;
    let before = ledger.snapshot();
    assert!(!spend.proof.matches_output_notes(&changed));
    assert!(ledger.apply_spend(&spend.proof, changed).is_err());
    assert_eq!(ledger.snapshot(), before);
    assert!(!ledger.is_spent(&opening.serial));
    ledger.apply_spend(&spend.proof, spend.notes).unwrap();
}

#[test]
fn native_security_regression_legacy_wire_and_changed_output_binding_fail_closed() {
    use qomm_defmi::notes::{decode_spend_proof, encode_spend_proof};
    let (ledger, owner, key, opening) = funded();
    let mut spend = ledger
        .build_spend(
            &[0],
            0,
            &opening,
            &key.g,
            &Scalar::ZERO,
            &[(owner.address, 1000)],
            b"wire",
            &mut OsRng,
        )
        .unwrap();
    let mut legacy = encode_spend_proof(&spend.proof).unwrap();
    legacy[..8].copy_from_slice(b"QOMMNSP1");
    assert!(decode_spend_proof(&legacy).is_err());
    spend.proof.output_notes[0][0] ^= 1;
    assert!(ledger
        .check_spend(&[0], &spend.proof, b"wire", &mut OsRng)
        .is_err());
}

#[test]
fn native_security_regression_issuer_signature_binds_the_note_decomposition() {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use qomm_defmi::notes::note_issuance_body;
    use zkfmi_crypto::{hybrid::signature::HybridSigner, key::KeyPurpose, traits::Signer};
    let key = Pedersen::new(b"qomm:defmi:v1");
    let issuer = HybridSigner::generate().unwrap();
    let mut ledger = NoteLedger::new(key.clone(), 32).under_issuer(issuer.public_key());
    let owner = Wallet::new(&mut OsRng);
    let blind = Scalar::random(&mut OsRng);
    let original = ledger
        .build_note(
            &owner.address,
            1000,
            key.commit_u64(1000, &blind),
            &blind,
            &mut OsRng,
        )
        .expect("valid fixture note encryption");
    let signature = issuer
        .sign(
            KeyPurpose::Attestation,
            &note_issuance_body(&ledger.commitment_of(&original), b"issuance"),
        )
        .unwrap();
    let mut forged = original.clone();
    forged.one_time -= G;
    forged.value_commitment += G;
    let before = ledger.snapshot();
    assert!(ledger.add_issued(forged, b"issuance", &signature).is_err());
    assert_eq!(ledger.snapshot(), before);
    ledger
        .add_issued(original, b"issuance", &signature)
        .unwrap();
}
