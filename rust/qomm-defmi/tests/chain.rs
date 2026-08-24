//! What a settlement contract must refuse, and what it must not leave behind.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use qomm_defmi::chain::{ChainState, Rejected};
use qomm_zk::pedersen::Pedersen;
use rand::rngs::OsRng;

fn point(seed: u64) -> RistrettoPoint {
    RistrettoPoint::mul_base(&Scalar::from(seed))
}

fn opened() -> ChainState {
    let mut state = ChainState::new();
    for (index, handle) in [b"sec:a".as_ref(), b"sec:b", b"cash:a", b"cash:b"]
        .iter()
        .enumerate()
    {
        state.open(handle, point(index as u64 + 1));
    }
    state
}

fn moves() -> Vec<(&'static [u8], RistrettoPoint)> {
    vec![
        (b"sec:a".as_ref(), point(11)),
        (b"sec:b".as_ref(), point(12)),
        (b"cash:a".as_ref(), point(13)),
        (b"cash:b".as_ref(), point(14)),
    ]
}

#[test]
fn a_settlement_writes_five_slots() {
    let mut state = opened();
    let delta = state.settle([7u8; 32], 1_000, 10, &moves()).unwrap();
    assert_eq!(delta.slots_written, 5); // four balances and one nullifier
    assert_eq!(delta.nullifiers_added, 1);
    assert_eq!(state.nullifiers(), 1);
}

#[test]
fn the_same_instruction_cannot_settle_twice() {
    let mut state = opened();
    state.settle([7u8; 32], 1_000, 10, &moves()).unwrap();
    assert_eq!(
        state.settle([7u8; 32], 1_000, 11, &moves()),
        Err(Rejected::NullifierSeen)
    );
}

#[test]
fn an_expired_instruction_is_refused() {
    let mut state = opened();
    match state.settle([7u8; 32], 100, 101, &moves()) {
        Err(Rejected::Expired { deadline, now }) => assert_eq!((deadline, now), (100, 101)),
        other => panic!("expected an expiry, got {other:?}"),
    }
}

#[test]
fn a_rejected_settlement_leaves_no_trace() {
    let mut state = opened();
    let before = state.root();
    let mut with_stranger = moves();
    with_stranger.push((b"sec:nobody".as_ref(), point(99)));
    assert_eq!(
        state.settle([7u8; 32], 1_000, 10, &with_stranger),
        Err(Rejected::UnknownAccount)
    );
    assert_eq!(
        state.root(),
        before,
        "a refused settlement changed the state"
    );
    assert_eq!(state.nullifiers(), 0);
}

#[test]
fn pruning_bounds_the_nullifier_set() {
    //  the property that makes this deployable: state tracks activity in one
    //  deadline window, not everything that ever settled
    let mut state = opened();
    for index in 0..500u64 {
        let mut nullifier = [0u8; 32];
        nullifier[..8].copy_from_slice(&index.to_be_bytes());
        state.settle(nullifier, 100 + index, 0, &moves()).unwrap();
    }
    assert_eq!(state.nullifiers(), 500);
    let dropped = state.prune(400);
    assert_eq!(dropped, 300);
    assert_eq!(state.nullifiers(), 200);
}

#[test]
fn an_expired_nullifier_is_safe_to_forget() {
    // dropping it does not let the instruction settle again, because the
    // deadline refuses it first
    let mut state = opened();
    state.settle([7u8; 32], 100, 10, &moves()).unwrap();
    state.prune(200);
    assert_eq!(state.nullifiers(), 0);
    assert!(matches!(
        state.settle([7u8; 32], 100, 200, &moves()),
        Err(Rejected::Expired { .. })
    ));
}

#[test]
fn nodes_agree_whatever_order_settlements_arrived_in() {
    let mut first = opened();
    let mut second = opened();
    let a = ([1u8; 32], 900u64);
    let b = ([2u8; 32], 950u64);
    first.settle(a.0, a.1, 10, &moves()).unwrap();
    first.settle(b.0, b.1, 11, &moves()).unwrap();
    second.settle(b.0, b.1, 11, &moves()).unwrap();
    second.settle(a.0, a.1, 10, &moves()).unwrap();
    assert_eq!(first.root(), second.root());
}

#[test]
fn the_root_separates_a_handle_from_the_key_after_it() {
    // lengths are hashed before the bytes, so "ab" + "c" cannot collide with
    // "a" + "bc"
    let mut first = ChainState::new();
    first.open(b"ab", point(1));
    first.open(b"c", point(2));
    let mut second = ChainState::new();
    second.open(b"a", point(1));
    second.open(b"bc", point(2));
    assert_ne!(first.root(), second.root());
}

#[test]
fn stored_bytes_track_what_is_held() {
    let mut state = opened();
    let base = state.stored_bytes();
    state.settle([7u8; 32], 1_000, 10, &moves()).unwrap();
    // balances are overwritten, so only the nullifier adds to what is stored
    assert_eq!(state.stored_bytes(), base + 40);
    let _ = OsRng; // the crate is a dev-dependency shared with the other tests
}

/// Two settlements that move one account do not commute, and the module says so.
///
/// The root is canonical given the state --- no node can disagree about the hash
/// of a state it agrees on --- and that is a different claim from "the same
/// settlements in any order give the same root", which the module used to make.
/// A settlement writes an absolute commitment rather than a delta, so the one
/// applied second is the one that survives. The ordering is consensus's job.
#[test]
fn settlements_that_move_one_account_do_not_commute() {
    let key = Pedersen::new(b"order");
    let mut rng = OsRng;
    let account = b"shared".to_vec();
    let first = key.commit_u64(10, &Scalar::random(&mut rng));
    let second = key.commit_u64(20, &Scalar::random(&mut rng));

    let root_after = |order: [(u8, RistrettoPoint); 2]| {
        let mut chain = ChainState::new();
        chain.open(&account, key.commit_u64(0, &Scalar::random(&mut OsRng)));
        for (tag, commitment) in order {
            chain
                .settle([tag; 32], 1_000, 1, &[(&account[..], commitment)])
                .unwrap();
        }
        chain.root()
    };

    assert_ne!(
        root_after([(1, first), (2, second)]),
        root_after([(2, second), (1, first)]),
        "the two orders agreed, so this test is not testing what it says"
    );

    // and the root is a function of the state, which is the claim that holds
    let mut a = ChainState::new();
    let mut b = ChainState::new();
    let opening = key.commit_u64(7, &Scalar::random(&mut rng));
    a.open(&account, opening);
    b.open(&account, opening);
    assert_eq!(a.root(), b.root());
}

/// An expired escrow goes back to its payer and cannot be claimed.
///
/// It used to record only the payee and the amount: no deadline to refuse a
/// late claim against, and no payer to give an expired one back to. An expired
/// leg still settled to the payee, an unclaimed one was stranded, and this map
/// and `Ledger` could reach different final states from the same leg.
#[test]
fn an_expired_escrow_goes_back_to_its_payer() {
    let key = Pedersen::new(b"escrow");
    let mut rng = OsRng;
    let mut chain = ChainState::new();
    let opening = |v: u64| key.commit_u64(v, &Scalar::random(&mut OsRng));
    chain.open(b"alice", opening(100));
    chain.open(b"bob", opening(0));
    chain
        .prepare(b"leg", b"alice", b"bob", opening(90), opening(10), 500)
        .unwrap();

    // late, so the payee cannot take it
    assert!(matches!(
        chain.claim(b"leg", opening(10), 501),
        Err(Rejected::Expired { .. })
    ));
    // and early, so the payer cannot take it back yet
    assert!(matches!(
        chain.unwind(b"leg", opening(100), 400),
        Err(Rejected::Expired { .. })
    ));

    assert_eq!(chain.escrows(), 1, "a refused call consumed the escrow");
    chain.unwind(b"leg", opening(100), 501).unwrap();
    assert_eq!(chain.escrows(), 0);

    // and within the deadline the payee can claim
    chain
        .prepare(b"leg2", b"alice", b"bob", opening(90), opening(10), 500)
        .unwrap();
    chain.claim(b"leg2", opening(10), 499).unwrap();
    assert_eq!(chain.escrows(), 0);
    let _ = &mut rng;
}
