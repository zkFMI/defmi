//! Notes: holdings that do not sit at an address.

use curve25519_dalek::scalar::Scalar;
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::notes::*;
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

const BITS: usize = 32;
const RING: usize = 8;

struct Pool {
    key: Pedersen,
    registry: AssetRegistry,
    ledger: NoteLedger,
    alice: Wallet,
    bob: Wallet,
    asset_key: Pedersen,
}

fn pool(rng: &mut OsRng) -> Pool {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let asset_key = key.with_value_generator(registry.tags[3]);
    let mut ledger = NoteLedger::new(key.clone(), BITS);
    let alice = Wallet::new(rng);
    let bob = Wallet::new(rng);
    for i in 0..RING {
        let owner = if i == 0 {
            alice.address
        } else {
            Wallet::new(rng).address
        };
        let value = 1_000 + i as u64;
        let blinding = Scalar::random(rng);
        let note = ledger.build_note(
            &owner,
            value,
            asset_key.commit_u64(value, &blinding),
            &blinding,
            rng,
        );
        ledger.add(note);
    }
    Pool {
        key,
        registry,
        ledger,
        alice,
        bob,
        asset_key,
    }
}

fn spend(
    p: &Pool,
    rng: &mut OsRng,
    tag_asset: u32,
    seed: u64,
) -> Result<(Vec<usize>, SpendProof, Vec<Note>), &'static str> {
    let found = p.ledger.scan(&p.alice, &p.asset_key);
    let (index, opening) = found[0];
    let (tag, gamma) = p.registry.blind(tag_asset, false, rng)?;
    let ring = ring_for(p.ledger.notes.len(), index, RING, seed)?;
    let spend = p.ledger.build_spend(
        &ring,
        index,
        &opening,
        &tag.point,
        &gamma,
        &[(p.bob.address, 400), (p.alice.address, opening.value - 400)],
        b"ctx",
        rng,
    )?;
    Ok((ring, spend.proof, spend.notes))
}

#[test]
fn a_spend_verifies_and_the_payee_finds_its_note() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let (ring, proof, notes) = spend(&p, &mut rng, 3, 7).unwrap();
    assert_eq!(
        p.ledger.check_spend(&ring, &proof, b"ctx", &mut rng),
        Ok(())
    );
    p.ledger.apply_spend(&proof, notes).unwrap();
    let received = p.ledger.scan(&p.bob, &p.asset_key);
    assert_eq!(
        received.iter().map(|(_, o)| o.value).collect::<Vec<_>>(),
        vec![400]
    );
}

#[test]
fn verifier_complete_spend_proof_round_trips_canonically() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let (ring, proof, _) = spend(&p, &mut rng, 3, 17).unwrap();
    let digest = proof.digest();
    let wire = encode_spend_proof(&proof).unwrap();
    let decoded = decode_spend_proof(&wire).unwrap();
    assert_eq!(decoded.digest(), digest);
    assert_eq!(
        p.ledger.check_spend(&ring, &decoded, b"ctx", &mut rng),
        Ok(())
    );
    let mut trailing = wire;
    trailing.push(0);
    assert!(decode_spend_proof(&trailing).is_err());
}

#[test]
fn a_hidden_input_can_be_bound_to_one_reservation_lock_class() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let (index, opening) = p.ledger.scan(&p.alice, &p.asset_key)[0];
    let ring = ring_for(p.ledger.notes.len(), index, RING, 41).unwrap();
    let position = ring
        .iter()
        .position(|candidate| *candidate == index)
        .unwrap();
    let mut eligibility = vec![false; ring.len()];
    eligibility[position] = true;
    let (tag, gamma) = p.registry.blind(3, false, &mut rng).unwrap();
    let spend = p
        .ledger
        .build_spend_constrained(
            &ring,
            index,
            &opening,
            &tag.point,
            &gamma,
            &[(p.bob.address, 400), (p.alice.address, opening.value - 400)],
            &eligibility,
            b"locked-hold",
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        p.ledger.check_spend_constrained(
            &ring,
            &spend.proof,
            &eligibility,
            b"locked-hold",
            &mut rng,
        ),
        Ok(())
    );

    let wrong_class = vec![true; ring.len()];
    assert_eq!(
        p.ledger.check_spend_constrained(
            &ring,
            &spend.proof,
            &wrong_class,
            b"locked-hold",
            &mut rng,
        ),
        Err("no note in the ring carries this serial")
    );
}

#[test]
fn a_prover_cannot_select_an_ineligible_decoy() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let (index, opening) = p.ledger.scan(&p.alice, &p.asset_key)[0];
    let ring = ring_for(p.ledger.notes.len(), index, RING, 42).unwrap();
    let eligibility = vec![false; ring.len()];
    let (tag, gamma) = p.registry.blind(3, false, &mut rng).unwrap();
    assert_eq!(
        p.ledger
            .build_spend_constrained(
                &ring,
                index,
                &opening,
                &tag.point,
                &gamma,
                &[(p.bob.address, opening.value)],
                &eligibility,
                b"wrong-lock",
                &mut rng,
            )
            .err(),
        Some("the selected note does not satisfy the spend constraint")
    );
}

#[test]
fn two_payments_to_one_address_are_unlinkable() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let mut made = Vec::new();
    for _ in 0..2 {
        let blinding = Scalar::random(&mut rng);
        let note = p.ledger.build_note(
            &p.bob.address,
            100,
            p.asset_key.commit_u64(100, &blinding),
            &blinding,
            &mut rng,
        );
        made.push(note.clone());
        p.ledger.add(note);
    }
    assert_ne!(
        p.ledger.commitment_of(&made[0]),
        p.ledger.commitment_of(&made[1])
    );
    assert_ne!(made[0].ephemeral, made[1].ephemeral);
    assert_eq!(p.ledger.scan(&p.bob, &p.asset_key).len(), 2);
}

#[test]
fn scanning_finds_only_your_own() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    assert_eq!(p.ledger.scan(&p.alice, &p.asset_key).len(), 1);
    assert!(p.ledger.scan(&p.bob, &p.asset_key).is_empty());
    assert!(p
        .ledger
        .scan(&Wallet::new(&mut rng), &p.asset_key)
        .is_empty());
}

#[test]
fn a_note_spends_once() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let (ring, proof, notes) = spend(&p, &mut rng, 3, 9).unwrap();
    p.ledger.apply_spend(&proof, notes).unwrap();
    assert_eq!(
        p.ledger.check_spend(&ring, &proof, b"ctx", &mut rng),
        Err("serial already spent")
    );
}

#[test]
fn a_reblinded_serial_cannot_stand_in_for_a_fresh_one() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let (ring, proof, notes) = spend(&p, &mut rng, 3, 11).unwrap();
    let shifted = proof.serial_point + p.key.h * Scalar::from(12_345u64);
    p.ledger.apply_spend(&proof, notes).unwrap();
    let replay = SpendProof {
        serial_point: shifted,
        ..proof
    };
    assert_eq!(
        p.ledger.check_spend(&ring, &replay, b"ctx", &mut rng),
        Err("the serial is not a bare power of the base point")
    );
}

#[test]
fn a_tag_for_the_wrong_asset_cannot_spend() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let (ring, proof, _) = spend(&p, &mut rng, 7, 13).unwrap();
    assert_eq!(
        p.ledger.check_spend(&ring, &proof, b"ctx", &mut rng),
        Err("no note in the ring carries this serial")
    );
}

#[test]
fn outputs_must_sum_to_the_note() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let found = p.ledger.scan(&p.alice, &p.asset_key);
    let (index, opening) = found[0];
    let (tag, gamma) = p.registry.blind(3, false, &mut rng).unwrap();
    let ring = ring_for(p.ledger.notes.len(), index, RING, 3).unwrap();
    assert_eq!(
        p.ledger
            .build_spend(
                &ring,
                index,
                &opening,
                &tag.point,
                &gamma,
                &[(p.bob.address, 400), (p.alice.address, 9_999)],
                b"ctx",
                &mut rng
            )
            .err(),
        Some("outputs do not sum to the note being spent")
    );
}

#[test]
fn the_spend_looks_the_same_wherever_the_real_note_sits() {
    let mut rng = OsRng;
    let p = pool(&mut rng);
    let mut shapes = std::collections::HashSet::new();
    for seed in 0..6u64 {
        let (ring, proof, _) = spend(&p, &mut rng, 3, seed).unwrap();
        assert_eq!(
            p.ledger.check_spend(&ring, &proof, b"ctx", &mut rng),
            Ok(())
        );
        shapes.insert((
            proof.ring.size_bytes(),
            proof.output_range.to_bytes().len(),
            proof.outputs.len(),
        ));
    }
    assert_eq!(shapes.len(), 1, "the hidden position leaks");
}

#[test]
fn the_pool_keeps_spent_notes() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let before = p.ledger.notes.len();
    let (_, proof, notes) = spend(&p, &mut rng, 3, 17).unwrap();
    p.ledger.apply_spend(&proof, notes).unwrap();
    assert_eq!(p.ledger.notes.len(), before + 2);
}

#[test]
fn a_ring_has_to_be_a_power_of_two_and_fit_the_pool() {
    assert!(ring_for(8, 0, 6, 1).is_err());
    assert!(ring_for(4, 0, 8, 1).is_err());
    assert!(ring_for(8, 0, 8, 1).is_ok());
}

#[test]
fn a_recent_ring_holds_the_note_and_stays_inside_the_pool() {
    for pool in [8usize, 64, 500] {
        for index in [0usize, pool / 2, pool - 1] {
            let ring = ring_recent(pool, index, 8, 32, 7).unwrap();
            assert_eq!(ring.len(), 8);
            assert!(
                ring.contains(&index),
                "the real note is not in its own ring"
            );
            assert!(ring.iter().all(|i| *i < pool), "a decoy is not in the pool");
            let mut sorted = ring.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), 8, "a decoy repeats");
        }
    }
}

/// The window is what the sampler is for, so it has to actually bind --- and
/// it has to stretch when the real note is older than it, because a window
/// that excluded the real note would name it outright.
#[test]
fn a_recent_ring_draws_from_the_window_and_widens_to_reach_the_note() {
    let ring = ring_recent(1000, 990, 8, 32, 3).unwrap();
    assert!(
        ring.iter().all(|i| *i >= 1000 - 32),
        "a decoy came from outside the window"
    );

    let ring = ring_recent(1000, 10, 8, 32, 3).unwrap();
    assert!(ring.contains(&10));
    assert!(
        ring.iter().all(|i| *i >= 10),
        "the window did not stretch to the note"
    );
}

#[test]
fn a_recent_ring_rejects_what_the_uniform_one_rejects() {
    assert!(ring_recent(8, 0, 6, 32, 1).is_err());
    assert!(ring_recent(4, 0, 8, 32, 1).is_err());
    assert!(ring_recent(8, 9, 8, 32, 1).is_err());
    assert!(ring_recent(8, 0, 8, 32, 1).is_ok());
}

/// The root is kept rather than recomputed, so what has to be pinned is that
/// keeping it says the same thing walking it did: every change moves it, and
/// two ledgers that saw the same changes agree.
#[test]
fn the_state_root_moves_on_every_change_and_agrees_across_ledgers() {
    let mut rng = OsRng;
    let mut p = pool(&mut rng);
    let mut seen = std::collections::HashSet::new();
    seen.insert(p.ledger.snapshot());
    assert_eq!(
        p.ledger.snapshot(),
        p.ledger.snapshot(),
        "reading it changes it"
    );

    let (_, proof, notes) = spend(&p, &mut rng, 3, 17).unwrap();
    p.ledger.apply_spend(&proof, notes).unwrap();
    assert!(
        seen.insert(p.ledger.snapshot()),
        "a spend left the root where it was"
    );

    let note = p.ledger.build_note(
        &Wallet::new(&mut rng).address,
        42,
        p.asset_key.commit_u64(42, &Scalar::ONE),
        &Scalar::ONE,
        &mut rng,
    );
    p.ledger.add(note);
    assert!(
        seen.insert(p.ledger.snapshot()),
        "an added note left the root alone"
    );
}

/// A pool built the same way twice has the same root, and one note of
/// difference is enough to part them.
#[test]
fn the_state_root_is_a_function_of_what_the_ledger_holds() {
    let mut rng = OsRng;
    let a = pool(&mut rng);
    let b = pool(&mut rng);
    assert_ne!(
        a.ledger.snapshot(),
        b.ledger.snapshot(),
        "two pools of different notes share a root"
    );

    let mut c = pool(&mut rng);
    let before = c.ledger.snapshot();
    let extra = c.ledger.build_note(
        &Wallet::new(&mut rng).address,
        7,
        c.asset_key.commit_u64(7, &Scalar::ONE),
        &Scalar::ONE,
        &mut rng,
    );
    c.ledger.add(extra);
    assert_ne!(
        before,
        c.ledger.snapshot(),
        "one more note did not move the root"
    );
}

/// The account rail got issuance control first and the note rail had none, so
/// any caller could mint a note and the pool's conservation was conservation
/// after admission there too.
#[test]
fn a_note_ledger_under_an_issuer_refuses_an_unsigned_note() {
    use ed25519_dalek::{Signer, SigningKey};
    use qomm_defmi::notes::note_issuance_body;

    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let issuer = SigningKey::generate(&mut rng);
    let asset_key = key.with_value_generator(AssetRegistry::new(key.clone(), 16).tags[3]);
    let mut ledger = NoteLedger::new(key.clone(), BITS).under_issuer(issuer.verifying_key());

    let owner = Wallet::new(&mut rng);
    let blinding = Scalar::random(&mut rng);
    let note = ledger.build_note(
        &owner.address,
        1_000,
        asset_key.commit_u64(1_000, &blinding),
        &blinding,
        &mut rng,
    );
    let body = note_issuance_body(&ledger.commitment_of(&note), b"n1");

    let elsewhere = SigningKey::generate(&mut rng);
    assert_eq!(
        ledger.add_issued(note.clone(), b"n1", &elsewhere.sign(&body)),
        Err("the note is not signed by the issuer")
    );

    let signature = issuer.sign(&body);
    assert!(ledger.add_issued(note.clone(), b"n1", &signature).is_ok());
    assert_eq!(
        ledger.add_issued(note, b"n1", &signature),
        Err("that issuance authorisation was already used")
    );
}

#[test]
#[should_panic(expected = "use add_issued")]
fn the_unchecked_append_is_closed_once_a_note_ledger_has_an_issuer() {
    use ed25519_dalek::SigningKey;
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let issuer = SigningKey::generate(&mut rng);
    let asset_key = key.with_value_generator(AssetRegistry::new(key.clone(), 16).tags[3]);
    let mut ledger = NoteLedger::new(key.clone(), BITS).under_issuer(issuer.verifying_key());
    let owner = Wallet::new(&mut rng);
    let blinding = Scalar::random(&mut rng);
    let note = ledger.build_note(
        &owner.address,
        1,
        asset_key.commit_u64(1, &blinding),
        &blinding,
        &mut rng,
    );
    ledger.add(note);
}
