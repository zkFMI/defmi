//! Delivery versus payment on ledgers that cannot read themselves.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey};
use qomm_defmi::assets::AssetRegistry;
use qomm_defmi::ledger::Ledger;
use qomm_defmi::settlement::*;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::handles::{Handle, Identity};
use qomm_zkpi::{deal_quorum, frost, Bounds, Instruction, Issuer, Venue};
use rand::rngs::OsRng;
use std::collections::BTreeMap;

const BITS: usize = 32;
const QTY: u64 = 100;
const PRICE: u64 = 99_990;
const SEC_BALANCE: u64 = 5_000;
const CASH_BALANCE: u64 = 50_000_000;

struct World {
    key: Pedersen,
    registry: AssetRegistry,
    defmi: Defmi,
    issuer: Issuer,
    shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
    sec: (u64, Scalar),
    cash: (u64, Scalar),
}

/// The two firms, named the way the design says they should be: one seed each,
/// a handle derived for this venue. The accounts a rail keeps their balances
/// under follow from those handles, so the test cannot open an account the
/// instruction would not name --- which is the property being fixed.
fn seller() -> Handle {
    Identity::from_seed([11u8; 32]).handle(VENUE)
}
fn buyer() -> Handle {
    Identity::from_seed([22u8; 32]).handle(VENUE)
}

const VENUE: &[u8] = b"defmi:test";

fn world(rng: &mut OsRng) -> World {
    world_with_cash_asset(rng, None)
}

/// The same, with the cash accounts opened under a currency's own tag.
///
/// A tagged cash *leg* over untagged cash *balances* does not verify, and it
/// should not: the remainder proof opens against the payer's existing balance,
/// so the tag has to be the one the balance already sits under. That refusal is
/// what binds the disguise to a real asset, and it is the same property the
/// securities rail relies on.
fn world_with_cash_asset(rng: &mut OsRng, cash_asset: Option<u32>) -> World {
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key.clone(), 16);
    let (secret, public) = deal_quorum(7, 3, rng).unwrap();
    let shares = secret
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let mut securities = Ledger::new(key.clone(), BITS);
    let mut cash = Ledger::new(key.clone(), BITS);

    let asset_key = key.with_value_generator(registry.tags[3]);
    let sec = (SEC_BALANCE, Scalar::random(rng));
    let cash_holding = (CASH_BALANCE, Scalar::random(rng));
    securities.open(
        &account_of(&seller().point, SECURITIES_RAIL),
        asset_key.commit_u64(sec.0, &sec.1),
    );
    securities.open(
        &account_of(&buyer().point, SECURITIES_RAIL),
        asset_key.commit_u64(0, &Scalar::random(rng)),
    );
    let cash_key = match cash_asset {
        Some(a) => key.with_value_generator(registry.tags[a as usize]),
        None => key.clone(),
    };
    cash.open(
        &account_of(&buyer().point, CASH_RAIL),
        cash_key.commit_u64(cash_holding.0, &cash_holding.1),
    );
    cash.open(
        &account_of(&seller().point, CASH_RAIL),
        cash_key.commit_u64(0, &Scalar::random(rng)),
    );

    let venue = Venue::new(key.clone(), &Bounds::default(), public.clone());
    World {
        issuer: Issuer::new(key.clone(), Bounds::default()),
        defmi: Defmi::new(key.clone(), securities, cash, venue),
        key,
        registry,
        shares,
        public,
        sec,
        cash: cash_holding,
    }
}

fn sign(w: &World, message: &[u8], rng: &mut OsRng) -> frost::Signature {
    let chosen: Vec<_> = w.shares.keys().take(3).cloned().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (n, c) = frost::round1::commit(w.shares[id].signing_share(), rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let package = frost::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for id in &chosen {
        shares.insert(
            *id,
            frost::round2::sign(&package, &nonces[id], &w.shares[id]).unwrap(),
        );
    }
    frost::aggregate(&package, &shares, &w.public).unwrap()
}

fn instruction(w: &World, rng: &mut OsRng, nonce: u8) -> (Instruction, InstructionOpenings) {
    let (digest, openings, partial) = w
        .issuer
        .build(
            QTY,
            PRICE,
            3,
            buyer().point,  // pays cash, receives securities
            seller().point, // delivers securities, receives cash
            1_500,
            [nonce; 32],
            1_599_845,
            rng,
        )
        .unwrap();
    let signature = sign(w, &digest, rng);
    (
        partial.sealed(signature),
        InstructionOpenings {
            amount: openings.amount,
            price: openings.price,
        },
    )
}

fn package(
    w: &World,
    rng: &mut OsRng,
    quantity: u64,
    price: u64,
    tag_asset: u32,
    nonce: u8,
) -> Result<DvpPackage, &'static str> {
    packaged(w, rng, quantity, price, tag_asset, nonce, None)
}

/// The same, with the cash rail carrying a tag of its own.
///
/// `cash_asset` of `None` is the single-currency case the rail was built for,
/// where hiding *which cash* means nothing. With more than one settlement
/// currency it means the same thing hiding the instrument does, and it is the
/// same construction applied once more.
fn packaged(
    w: &World,
    rng: &mut OsRng,
    quantity: u64,
    price: u64,
    tag_asset: u32,
    nonce: u8,
    cash_asset: Option<u32>,
) -> Result<DvpPackage, &'static str> {
    let (instruction, openings) = instruction(w, rng, nonce);
    let (tag, gamma) = w.registry.blind(tag_asset, false, rng).unwrap();
    let cash = cash_asset.map(|a| w.registry.blind(a, false, rng).unwrap());
    let (cash_tag, cash_gamma) = match &cash {
        Some((t, g)) => (Some(t), *g),
        None => (None, Scalar::ZERO),
    };
    build_package(
        &w.key,
        instruction,
        &w.defmi.securities,
        &w.defmi.cash,
        quantity,
        price,
        &Holdings {
            securities_balance: w.sec.0,
            securities_blinding: w.sec.1,
            cash_balance: w.cash.0,
            cash_blinding: w.cash.1,
        },
        &openings,
        Some(&tag),
        &gamma,
        cash_tag,
        &cash_gamma,
        rng,
    )
    .map(|(p, _)| p)
}

#[test]
fn a_valid_delivery_versus_payment_settles() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE, 3, 1).unwrap();
    let receipt = w.defmi.settle(&p, 1_000, &mut rng);
    assert_eq!(receipt.status, Ok(()));
    assert!(w.defmi.solvent());
    assert_ne!(receipt.securities_before, receipt.securities_after);
    assert_ne!(receipt.cash_before, receipt.cash_after);
}

#[test]
fn delivering_the_wrong_quantity_is_rejected() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY + 1, PRICE, 3, 2).unwrap();
    assert!(w.defmi.settle(&p, 1_000, &mut rng).status.is_err());
    assert!(w.defmi.solvent());
}

#[test]
fn paying_the_wrong_amount_is_rejected() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE - 10, 3, 3).unwrap();
    assert!(w.defmi.settle(&p, 1_000, &mut rng).status.is_err());
}

#[test]
fn nothing_moves_when_a_leg_fails() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let before_sec = w.defmi.securities.snapshot();
    let before_cash = w.defmi.cash.snapshot();
    let p = package(&w, &mut rng, QTY, PRICE + 7, 3, 4).unwrap();
    assert!(w.defmi.settle(&p, 1_000, &mut rng).status.is_err());
    assert_eq!(w.defmi.securities.snapshot(), before_sec);
    assert_eq!(w.defmi.cash.snapshot(), before_cash);
}

#[test]
fn an_instruction_settles_at_most_once() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE, 3, 5).unwrap();
    assert_eq!(w.defmi.settle(&p, 1_000, &mut rng).status, Ok(()));
    assert_eq!(
        w.defmi.settle(&p, 1_000, &mut rng).status,
        Err("already settled")
    );
}

#[test]
fn an_expired_instruction_does_not_settle() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE, 3, 6).unwrap();
    assert_eq!(
        w.defmi.settle(&p, 2_000, &mut rng).status,
        Err("past the deadline")
    );
}

#[test]
fn a_tag_for_the_wrong_asset_cannot_move_the_balance() {
    // the remainder proof is what binds the disguise to the real asset
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = package(&w, &mut rng, QTY, PRICE, 7, 7).unwrap();
    assert!(w.defmi.settle(&p, 1_000, &mut rng).status.is_err());
    assert!(w.defmi.solvent());
}

#[test]
fn the_package_looks_the_same_whatever_the_asset() {
    let mut rng = OsRng;
    let mut sizes = std::collections::HashSet::new();
    for (i, asset) in [0u32, 3, 7, 15].iter().enumerate() {
        let key = Pedersen::new(b"qomm:defmi:v1");
        let registry = AssetRegistry::new(key.clone(), 16);
        let mut w = world(&mut rng);
        let asset_key = key.with_value_generator(registry.tags[*asset as usize]);
        let mut securities = Ledger::new(key.clone(), BITS);
        securities.open(
            &account_of(&seller().point, SECURITIES_RAIL),
            asset_key.commit_u64(SEC_BALANCE, &w.sec.1),
        );
        securities.open(
            &account_of(&buyer().point, SECURITIES_RAIL),
            asset_key.commit_u64(0, &Scalar::random(&mut rng)),
        );
        w.defmi.securities = securities;
        w.registry = registry;
        let p = package(&w, &mut rng, QTY, PRICE, *asset, 20 + i as u8).unwrap();
        assert_eq!(w.defmi.settle(&p, 1_000, &mut rng).status, Ok(()));
        sizes.insert(wire_size(&p));
    }
    assert_eq!(sizes.len(), 1, "the asset leaks through the package size");
}

fn wire_size(p: &DvpPackage) -> usize {
    // compressed points and scalars are 32 bytes each; range proofs report
    // their own length
    let ranges = p.securities_leg.remainder_range.to_bytes().len()
        + p.cash_leg.remainder_range.to_bytes().len()
        + p.instruction.range_proof_bytes_len();
    let points = 3 /* leg commitments */ + 2 /* tag */ + 3 /* instruction */
        + 2 /* link */ + 2 /* product */ + 2 /* handles */;
    let scalars = 3 /* link */ + 3 /* product */;
    ranges + 32 * (points + scalars) + 64 /* signature */ + 32 /* nonce */
}

#[test]
fn a_stale_range_proof_on_a_bounded_amount_is_refused() {
    let mut rng = OsRng;
    let w = world(&mut rng);
    let (transfer, _) = w
        .defmi
        .securities
        .build_transfer(
            SEC_BALANCE,
            &w.sec.1,
            QTY,
            b"ctx",
            None,
            &Scalar::ZERO,
            false,
            &mut rng,
        )
        .unwrap();
    assert!(transfer.amount_range.is_some());
    assert_eq!(
        w.defmi.securities.check_transfer(
            &account_of(&seller().point, SECURITIES_RAIL),
            &transfer,
            b"ctx",
            true
        ),
        Err("an externally bounded amount carries a stale range proof")
    );
}

#[test]
fn issuance_carries_a_proof_that_the_asset_is_listed() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let registry = AssetRegistry::new(key, 16);
    let (tag, _) = registry.blind(5, true, &mut rng).unwrap();
    assert!(registry.verify_membership(&tag));
    let (bare, _) = registry.blind(5, false, &mut rng).unwrap();
    assert!(!registry.verify_membership(&bare));
    assert!(registry.blind(99, false, &mut rng).is_err());
}

/// A package that arrives over the wire naming other accounts.
///
/// `build_package` derives the four names from the instruction, so an honest
/// caller cannot produce this; it is made by editing a good package, which is
/// what a wire lets anyone do. Before the accounts were derived there was
/// nothing to catch it: the instruction named two group elements, the package
/// named four byte strings, and the two were never compared.
#[test]
fn a_package_cannot_name_accounts_the_instruction_does_not() {
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let good = package(&w, &mut rng, QTY, PRICE, 3, 1).unwrap();
    assert_eq!(w.defmi.settle(&good, 1_000, &mut rng).status, Ok(()));

    // pay the securities to somebody else
    let mut w = world(&mut rng);
    let mut tampered = package(&w, &mut rng, QTY, PRICE, 3, 2).unwrap();
    let stranger = Identity::from_seed([99u8; 32]).handle(VENUE);
    tampered.securities_to = account_of(&stranger.point, SECURITIES_RAIL);
    assert_eq!(
        w.defmi.settle(&tampered, 1_000, &mut rng).status,
        Err("the package names accounts the instruction does not")
    );

    // or take the cash from somebody else
    let mut w = world(&mut rng);
    let mut tampered = package(&w, &mut rng, QTY, PRICE, 3, 3).unwrap();
    tampered.cash_from = account_of(&seller().point, CASH_RAIL);
    assert_eq!(
        w.defmi.settle(&tampered, 1_000, &mut rng).status,
        Err("the package names accounts the instruction does not")
    );

    // or run the whole thing backwards
    let mut w = world(&mut rng);
    let mut tampered = package(&w, &mut rng, QTY, PRICE, 3, 4).unwrap();
    std::mem::swap(&mut tampered.cash_from, &mut tampered.cash_to);
    std::mem::swap(&mut tampered.securities_from, &mut tampered.securities_to);
    assert_eq!(
        w.defmi.settle(&tampered, 1_000, &mut rng).status,
        Err("the package names accounts the instruction does not")
    );
}

/// Two firms at one venue get different accounts on each rail, and one firm's
/// two rails do not share a name.
#[test]
fn accounts_are_a_function_of_the_handle_and_the_rail() {
    let (a, b) = (seller().point, buyer().point);
    assert_ne!(
        account_of(&a, SECURITIES_RAIL),
        account_of(&b, SECURITIES_RAIL)
    );
    assert_ne!(account_of(&a, SECURITIES_RAIL), account_of(&a, CASH_RAIL));
    assert_eq!(account_of(&a, CASH_RAIL), account_of(&a, CASH_RAIL));
}

// --- who is allowed to create balance ---------------------------------------
//
// `open` used to take any commitment and fold it into `minted`, so the
// conservation check said "nothing has been created or destroyed since the
// ledger accepted these" and not "only an issuer created anything". Anyone who
// could call it could mint.

#[test]
fn a_ledger_under_an_issuer_refuses_an_unsigned_opening() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let issuer = SigningKey::generate(&mut rng);
    let mut ledger = Ledger::under_issuer(key.clone(), 32, issuer.verifying_key());
    let balance = key.commit_u64(1_000, &Scalar::random(&mut rng));
    let elsewhere = SigningKey::generate(&mut rng);
    let body = qomm_defmi::ledger::issuance_body(b"alice", &balance, b"n1");
    assert_eq!(
        ledger.open_authorised(b"alice", balance, b"n1", &elsewhere.sign(&body)),
        Err("the opening balance is not signed by the issuer")
    );
}

#[test]
fn an_issued_opening_is_admitted_once_and_not_twice() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let issuer = SigningKey::generate(&mut rng);
    let mut ledger = Ledger::under_issuer(key.clone(), 32, issuer.verifying_key());
    let balance = key.commit_u64(1_000, &Scalar::random(&mut rng));
    let body = qomm_defmi::ledger::issuance_body(b"alice", &balance, b"n1");
    let signature = issuer.sign(&body);
    assert_eq!(
        ledger.open_authorised(b"alice", balance, b"n1", &signature),
        Ok(())
    );
    assert_eq!(
        ledger.open_authorised(b"alice", balance, b"n1", &signature),
        Err("handle already open")
    );
    assert_eq!(
        ledger.open_authorised(b"bob", balance, b"n1", &signature),
        Err("the opening balance is not signed by the issuer"),
        "an authorisation moved to another handle"
    );
}

#[test]
fn an_authorisation_does_not_carry_to_another_amount() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let issuer = SigningKey::generate(&mut rng);
    let mut ledger = Ledger::under_issuer(key.clone(), 32, issuer.verifying_key());
    let small = key.commit_u64(1, &Scalar::random(&mut rng));
    let large = key.commit_u64(1_000_000, &Scalar::random(&mut rng));
    let signature = issuer.sign(&qomm_defmi::ledger::issuance_body(b"alice", &small, b"n1"));
    assert_eq!(
        ledger.open_authorised(b"alice", large, b"n1", &signature),
        Err("the opening balance is not signed by the issuer")
    );
}

#[test]
#[should_panic(expected = "use open_authorised")]
fn the_unchecked_opening_is_closed_once_a_ledger_has_an_issuer() {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let issuer = SigningKey::generate(&mut rng);
    let mut ledger = Ledger::under_issuer(key.clone(), 32, issuer.verifying_key());
    ledger.open(b"alice", key.commit_u64(1_000, &Scalar::random(&mut rng)));
}

// --- a cash rail with a currency of its own --------------------------------

#[test]
fn a_tagged_cash_rail_settles_the_same_way() {
    // The last thing on `DEFMI.md`'s missing list that was a build rather than
    // a statement of an inherent limit: the cash leg could not carry a tag, so
    // a second settlement currency had nowhere to hide.
    let mut rng = OsRng;
    let mut w = world_with_cash_asset(&mut rng, Some(0));
    let p = packaged(&w, &mut rng, QTY, PRICE, 3, 1, Some(0)).unwrap();
    let receipt = w.defmi.settle(&p, 1_000, &mut rng);
    assert_eq!(receipt.status, Ok(()));
}

#[test]
fn a_tagged_cash_leg_over_untagged_balances_is_refused() {
    // The property that binds the disguise to a real asset: the remainder proof
    // opens against the balance the payer already has, so a leg cannot claim a
    // currency the account is not denominated in.
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let p = packaged(&w, &mut rng, QTY, PRICE, 3, 1, Some(0)).unwrap();
    assert_eq!(
        w.defmi.settle(&p, 1_000, &mut rng).status,
        Err("remainder does not equal balance minus amount")
    );
}

#[test]
fn a_tagged_cash_leg_moved_to_another_currency_is_refused() {
    let mut rng = OsRng;
    let mut w = world_with_cash_asset(&mut rng, Some(0));
    let mut p = packaged(&w, &mut rng, QTY, PRICE, 3, 1, Some(0)).unwrap();
    // re-tag the leg without redoing the link
    let (elsewhere, _) = w.registry.blind(1, false, &mut rng).unwrap();
    p.cash_leg.tag = Some(elsewhere);
    let receipt = w.defmi.settle(&p, 1_000, &mut rng);
    assert!(receipt.status.is_err());
}

#[test]
fn the_reference_the_product_is_about_cannot_be_swapped() {
    // The reference is what ties `quantity * price` to the leg. Moving it moves
    // the amount the cash rail is being asked to transfer, which is the whole
    // reason it is a separate commitment with a link rather than the leg itself.
    let mut rng = OsRng;
    let mut w = world_with_cash_asset(&mut rng, Some(0));
    let mut p = packaged(&w, &mut rng, QTY, PRICE, 3, 1, Some(0)).unwrap();
    p.cash_reference = w.key.commit_u64(QTY * PRICE + 1, &Scalar::random(&mut rng));
    let receipt = w.defmi.settle(&p, 1_000, &mut rng);
    assert!(receipt.status.is_err());
}

#[test]
fn an_untagged_cash_rail_still_settles_and_the_package_is_the_same_shape() {
    // The link is a proof of the obvious when the generators coincide, and
    // paying for it is the price of not having two package shapes on the wire.
    let mut rng = OsRng;
    let mut w = world(&mut rng);
    let tagged = packaged(&w, &mut rng, QTY, PRICE, 3, 1, Some(0)).unwrap();
    let bare = packaged(&w, &mut rng, QTY, PRICE, 3, 2, None).unwrap();
    assert_eq!(
        tagged.cash_link.z_value.to_bytes().len(),
        bare.cash_link.z_value.to_bytes().len()
    );
    let receipt = w.defmi.settle(&bare, 1_000, &mut rng);
    assert_eq!(receipt.status, Ok(()));
}
