use curve25519_dalek::scalar::Scalar;
use qomm_proofs::price_limit::{prove, verify, PriceLimitDirection};
use qomm_zk::pedersen::Pedersen;
use rand_core::OsRng;

#[test]
fn buy_quote_must_not_exceed_hidden_maximum() {
    let key = Pedersen::new(b"qomm:price-limit:test");
    let quote_blinding = Scalar::random(&mut OsRng);
    let limit_blinding = Scalar::random(&mut OsRng);
    let proof = prove(
        &key,
        98,
        &quote_blinding,
        100,
        &limit_blinding,
        PriceLimitDirection::MaximumBuyPrice,
        32,
        b"rfq-1",
    )
    .unwrap();
    verify(
        &key,
        &key.commit_u64(98, &quote_blinding),
        &key.commit_u64(100, &limit_blinding),
        PriceLimitDirection::MaximumBuyPrice,
        32,
        b"rfq-1",
        &proof,
    )
    .unwrap();
    assert!(verify(
        &key,
        &key.commit_u64(98, &quote_blinding),
        &key.commit_u64(100, &limit_blinding),
        PriceLimitDirection::MaximumBuyPrice,
        32,
        b"another-rfq",
        &proof,
    )
    .is_err());
}

#[test]
fn sell_quote_below_hidden_minimum_cannot_be_proved() {
    let key = Pedersen::new(b"qomm:price-limit:test");
    assert!(prove(
        &key,
        99,
        &Scalar::random(&mut OsRng),
        100,
        &Scalar::random(&mut OsRng),
        PriceLimitDirection::MinimumSellPrice,
        32,
        b"rfq-2",
    )
    .is_err());
}
