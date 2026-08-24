//! The public single-leg settlement entry point verifies against current state
//! on every call. It exists for chain adapters and cannot be a replay shortcut.

use curve25519_dalek::scalar::Scalar;
use qomm_defmi::ledger::Ledger;
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

#[test]
fn one_checked_transfer_settles_and_an_exact_replay_is_refused() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:atomic-test");
    let mut ledger = Ledger::new(key.clone(), 32);
    let payer_blinding = Scalar::random(&mut rng);
    ledger.open(b"payer", key.commit_u64(1_000, &payer_blinding));
    ledger.open(b"payee", key.commit_u64(0, &Scalar::random(&mut rng)));
    let (transfer, _) = ledger
        .build_transfer(
            1_000,
            &payer_blinding,
            100,
            b"atomic",
            None,
            &Scalar::ZERO,
            false,
            &mut rng,
        )
        .unwrap();

    assert_eq!(
        ledger.settle_transfer(b"payer", b"payee", &transfer, b"atomic", false),
        Ok(())
    );
    let after = ledger.snapshot();
    assert!(ledger
        .settle_transfer(b"payer", b"payee", &transfer, b"atomic", false)
        .is_err());
    assert_eq!(ledger.snapshot(), after, "a refused replay changed state");
    assert!(ledger.conserved());
}

#[test]
fn an_unknown_payee_is_refused_before_state_changes() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:atomic-test");
    let mut ledger = Ledger::new(key.clone(), 32);
    let payer_blinding = Scalar::random(&mut rng);
    ledger.open(b"payer", key.commit_u64(1_000, &payer_blinding));
    let (transfer, _) = ledger
        .build_transfer(
            1_000,
            &payer_blinding,
            100,
            b"atomic",
            None,
            &Scalar::ZERO,
            false,
            &mut rng,
        )
        .unwrap();
    let before = ledger.snapshot();
    assert_eq!(
        ledger.settle_transfer(b"payer", b"missing", &transfer, b"atomic", false),
        Err("unknown payee handle")
    );
    assert_eq!(ledger.snapshot(), before);
}
