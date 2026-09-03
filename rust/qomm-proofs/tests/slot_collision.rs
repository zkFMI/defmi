//! Why `n_slots` has to be at least the number of makers.
//!
//! The key a maker is ranked by is `(gated + 2*sentinel) * n_slots + index`, and
//! the verifier rebuilds it in the exponent from the maker's own gated
//! commitment and its own index. That is a bijection on `(cost, index)` only
//! while `index < n_slots`. Past that it wraps, and two different makers at two
//! different costs produce the *same* key commitment --- so a proof that the
//! opened key is the minimum no longer says which maker it belongs to.
//!
//! produced `artifacts/threshold_assembly.json` ran sixteen makers into eight
//! slots. The paper cites a number from that row. `QuoteCircuit::prove` now
//! refuses the configuration; this is the arithmetic that says why.

use curve25519_dalek::scalar::Scalar;
use qomm_zk::pedersen::Pedersen;

fn key() -> Pedersen {
    Pedersen::new(b"qomm:test:slot-collision")
}

/// The verifier's own derivation, with the blinding left out because the
/// collision is in the exponent of the value generator and does not need it.
fn derived_key(
    key: &Pedersen,
    gated: i64,
    sentinel: i64,
    n_slots: i64,
    index: u64,
) -> curve25519_dalek::ristretto::RistrettoPoint {
    let inner = key.commit(&Scalar::from(gated as u64), &Scalar::ZERO)
        + key.commit(&Scalar::from((2 * sentinel) as u64), &Scalar::ZERO);
    inner * Scalar::from(n_slots as u64) + key.commit(&Scalar::from(index), &Scalar::ZERO)
}

#[test]
fn a_sixteenth_maker_in_eight_slots_shares_a_key_with_the_first() {
    let key = key();
    let sentinel = 1 << 20;
    let n_slots = 8;

    // Maker 8 at gated cost `c`, and maker 0 at gated cost `c + 1`.
    let cost = 5;
    let ninth = derived_key(&key, cost, sentinel, n_slots, 8);
    let first = derived_key(&key, cost + 1, sentinel, n_slots, 0);

    assert_eq!(
        ninth.compress(),
        first.compress(),
        "two makers at two costs must not rank as the same key"
    );

    // And the packing that stands behind it, in the plain.
    assert_eq!(cost * n_slots + 8, (cost + 1) * n_slots);
}

#[test]
fn the_same_two_are_distinct_once_the_slots_cover_the_makers() {
    let key = key();
    let sentinel = 1 << 20;
    let n_slots = 16;

    let cost = 5;
    let ninth = derived_key(&key, cost, sentinel, n_slots, 8);
    let first = derived_key(&key, cost + 1, sentinel, n_slots, 0);

    assert_ne!(
        ninth.compress(),
        first.compress(),
        "with a slot for every maker the key determines the maker"
    );
}
