//!
//! The claim is that interposing a house costs two point additions and no
//! proof, because it rewrites the obligation graph rather than asserting
//! anything about it. So the tests are about the rewrite being a rewrite ---
//! same amounts, every edge through the house, the book flat.
//!
//! The two that matter most are the ones about what a house *cannot* do. It
//! cannot invent an edge, because both parties sign their own; and a member
//! cleared at two houses gets two resolutions and no netted one, because
//! cross-margining is an agreement and not an identity.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{SigningKey, VerifyingKey};
use qomm_defmi::ccp::*;
use qomm_defmi::credit::{CreditCtx, Tranche};
use qomm_zk::pedersen::{encode, Pedersen};
use rand::rngs::OsRng;
use rand::Rng;

const ASSET: &str = "an instrument";

fn key() -> Pedersen {
    Pedersen::new(b"qomm:defmi:v1").with_value_generator(qomm_zk::pedersen::asset_tag(7))
}

struct Room {
    key: Pedersen,
    members: Vec<Vec<u8>>,
    signing: BTreeMap<Vec<u8>, SigningKey>,
    parties: BTreeMap<Vec<u8>, VerifyingKey>,
}

fn room(n: usize) -> Room {
    let mut rng = OsRng;
    let mut members = Vec::new();
    let mut signing = BTreeMap::new();
    let mut parties = BTreeMap::new();
    for i in 0..n {
        let handle = format!("p{i}").into_bytes();
        let sk = SigningKey::generate(&mut rng);
        parties.insert(handle.clone(), sk.verifying_key());
        signing.insert(handle.clone(), sk);
        members.push(handle);
    }
    Room {
        key: key(),
        members,
        signing,
        parties,
    }
}

impl Room {
    fn graph(&self, edges: usize, asset: &str) -> Vec<SignedObligation> {
        let mut rng = OsRng;
        let mut out = Vec::new();
        for i in 0..edges {
            let payer = self.members[i % self.members.len()].clone();
            let payee = self.members[(i + 1) % self.members.len()].clone();
            let obligation = Obligation {
                payer: payer.clone(),
                payee: payee.clone(),
                asset: asset.to_string(),
                commitment: self
                    .key
                    .commit_u64(rng.gen_range(1..1000), &Scalar::random(&mut rng)),
            };
            out.push(sign_obligation(
                &obligation,
                &self.signing[&payer],
                &self.signing[&payee],
            ));
        }
        out
    }
}

fn house(name: &str, handle: &[u8]) -> ClearingProvider {
    ClearingProvider::new(name, handle, SigningKey::generate(&mut OsRng))
}

fn margined(ctx: &CreditCtx, handle: &[u8]) -> qomm_defmi::credit::CreditLine {
    let mut rng = OsRng;
    ctx.grant(
        handle,
        "cash",
        8_000_000,
        &Scalar::random(&mut rng),
        10_000_000,
        &Scalar::random(&mut rng),
        500,
    )
    .unwrap()
}

fn four_layers(k: &Pedersen, name: &str) -> ProviderWaterfall {
    let mut rng = OsRng;
    let mut layer = |v: u64| k.commit_u64(v, &Scalar::random(&mut rng));
    for_provider(name, layer(100), layer(200), layer(400), layer(5_000))
}

// --- the rewrite is a rewrite ---------------------------------------------

#[test]
fn every_edge_goes_through_the_house_and_the_book_is_flat() {
    let room = room(6);
    let h = house("DeCCP-A", b"house-a");
    let novation = h.novate(&room.graph(12, ASSET)).unwrap();
    assert_eq!(novation.edges(), 12);
    assert_eq!(novation.after.len(), 24);
    assert_eq!(check_novation(&h.handle, &novation), Ok(()));
}

#[test]
fn the_flat_book_needs_no_proof_at_any_size() {
    // It is an identity. If it ever needed establishing, novation would be
    // asserting something instead of rewriting the graph.
    let room = room(5);
    let h = house("DeCCP-A", b"house-a");
    for n in [1usize, 2, 17, 64] {
        let novation = h.novate(&room.graph(n, ASSET)).unwrap();
        assert_eq!(
            encode(&novation.owed_to_house),
            encode(&novation.owed_by_house)
        );
        assert_eq!(check_novation(&h.handle, &novation), Ok(()));
    }
}

#[test]
fn an_amount_changed_on_the_way_through_is_caught() {
    let mut rng = OsRng;
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let mut novation = h.novate(&room.graph(6, ASSET)).unwrap();
    novation.after[4].commitment = room.key.commit_u64(1, &Scalar::random(&mut rng));
    assert!(check_novation(&h.handle, &novation)
        .unwrap_err()
        .contains("changed amount"));
}

#[test]
fn an_edge_that_does_not_touch_the_house_is_caught() {
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let mut novation = h.novate(&room.graph(6, ASSET)).unwrap();
    novation.after[0].payee = b"somebody-else".to_vec();
    assert!(check_novation(&h.handle, &novation).is_err());
}

#[test]
fn a_graph_that_mixes_assets_is_refused_at_the_start() {
    // Commitments under different tags do not combine, so a mixed graph must
    // fail here rather than net one instrument out as another.
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let mut edges = room.graph(4, ASSET);
    edges.extend(room.graph(1, "a different instrument"));
    assert_eq!(
        h.novate(&edges).err(),
        Some("an obligation graph is per asset")
    );
}

#[test]
fn a_novation_attributed_to_another_house_is_caught() {
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let novation = h.novate(&room.graph(4, ASSET)).unwrap();
    assert!(check_novation(b"house-b", &novation)
        .unwrap_err()
        .contains("different house"));
}

#[test]
fn net_positions_accumulate_without_a_proof() {
    let room = room(5);
    let h = house("DeCCP-A", b"house-a");
    let novation = h.novate(&room.graph(20, ASSET)).unwrap();
    let nets = net_positions(&novation);
    let mut owed = RistrettoPoint::identity();
    let mut claim = RistrettoPoint::identity();
    for (obligation, entitlement) in nets.values() {
        owed += obligation;
        claim += entitlement;
    }
    // every edge appears once as an obligation and once as a claim
    assert_eq!(encode(&owed), encode(&claim));
}

// --- the hole that is now closed: a house cannot invent a trade ------------

#[test]
fn both_parties_have_to_have_signed() {
    let room = room(4);
    let edges = room.graph(3, ASSET);
    for edge in &edges {
        assert_eq!(
            check_agreement(
                edge,
                &room.parties[&edge.obligation.payer],
                &room.parties[&edge.obligation.payee]
            ),
            Ok(())
        );
    }
}

#[test]
fn a_house_cannot_novate_a_trade_nobody_agreed_to() {
    // the opposite outcome, which is the point of the pair of signatures.
    let mut rng = OsRng;
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let ctx = CreditCtx::new(Pedersen::new(b"qomm:defmi:v1"), 64);
    let mut registry = ClearingRegistry::new();
    registry
        .admit(
            &ctx,
            &h,
            margined(&ctx, &h.handle),
            four_layers(&room.key, "DeCCP-A"),
        )
        .unwrap();

    // the house makes up an edge and signs both halves with its own key
    let invented = Obligation {
        payer: room.members[0].clone(),
        payee: room.members[1].clone(),
        asset: ASSET.to_string(),
        commitment: room.key.commit_u64(999, &Scalar::random(&mut rng)),
    };
    let forged = SigningKey::generate(&mut rng);
    let edges = vec![sign_obligation(&invented, &forged, &forged)];
    let novation = h.novate(&edges).unwrap();
    let attestation = h.attest(&novation, b"cycle-1");

    // the arithmetic still checks out --- and the agreement does not
    assert_eq!(check_novation(&h.handle, &novation), Ok(()));
    let why = registry
        .check_cycle(&attestation, &novation, &room.parties)
        .unwrap_err();
    assert!(why.contains("payer did not sign"), "{why}");
}

#[test]
fn a_party_that_is_not_known_to_the_room_is_refused() {
    let mut rng = OsRng;
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let ctx = CreditCtx::new(Pedersen::new(b"qomm:defmi:v1"), 64);
    let mut registry = ClearingRegistry::new();
    registry
        .admit(
            &ctx,
            &h,
            margined(&ctx, &h.handle),
            four_layers(&room.key, "DeCCP-A"),
        )
        .unwrap();
    let stranger = SigningKey::generate(&mut rng);
    let obligation = Obligation {
        payer: b"nobody".to_vec(),
        payee: room.members[0].clone(),
        asset: ASSET.to_string(),
        commitment: room.key.commit_u64(5, &Scalar::random(&mut rng)),
    };
    let edges = vec![sign_obligation(
        &obligation,
        &stranger,
        &room.signing[&room.members[0]],
    )];
    let novation = h.novate(&edges).unwrap();
    let attestation = h.attest(&novation, b"c");
    assert!(registry
        .check_cycle(&attestation, &novation, &room.parties)
        .unwrap_err()
        .contains("not a known party"));
}

#[test]
fn what_a_house_can_still_do_is_leave_a_trade_out() {
    // Stated as a test because it is what remains after the signatures, and it
    // is a different shape of failure: the parties hold the signed obligation,
    // so an omission is arguable where an invention would have been invisible.
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let edges = room.graph(6, ASSET);
    let dropped = h.novate(&edges[..5]).unwrap();
    assert_eq!(check_novation(&h.handle, &dropped), Ok(()));
    assert_eq!(dropped.edges(), 5);
    // and the party to the missing edge can still show it agreed to it
    let missing = &edges[5];
    assert_eq!(
        check_agreement(
            missing,
            &room.parties[&missing.obligation.payer],
            &room.parties[&missing.obligation.payee]
        ),
        Ok(())
    );
}

// --- the attestation, and what stands behind it ---------------------------

#[test]
fn an_attestation_over_a_different_trade_set_is_caught() {
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let first = h.novate(&room.graph(4, ASSET)).unwrap();
    let second = h.novate(&room.graph(4, ASSET)).unwrap();
    let attestation = h.attest(&first, b"cycle-1");
    assert_eq!(
        check_attestation(&attestation, &second, &h.verifying_key()).err(),
        Some("the attestation is over a different trade set")
    );
}

#[test]
fn the_same_trades_in_a_different_cycle_do_not_share_an_attestation() {
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let novation = h.novate(&room.graph(4, ASSET)).unwrap();
    assert_ne!(
        h.attest(&novation, b"cycle-1").digest,
        h.attest(&novation, b"cycle-2").digest
    );
}

#[test]
fn a_provider_with_no_tranche_of_its_own_is_not_admitted() {
    let mut rng = OsRng;
    let room = room(3);
    let h = house("DeCCP-A", b"house-a");
    let ctx = CreditCtx::new(Pedersen::new(b"qomm:defmi:v1"), 64);
    let bare = ProviderWaterfall {
        provider: "DeCCP-A".into(),
        tranches: vec![Tranche {
            name: "mutualised pool".into(),
            commitment: room.key.commit_u64(1, &Scalar::random(&mut rng)),
        }],
        own: 1, // past the end: there is no layer of its own
    };
    let why = ClearingRegistry::new()
        .admit(&ctx, &h, margined(&ctx, &h.handle), bare)
        .unwrap_err();
    assert!(why.contains("costs it nothing to get wrong"), "{why}");
}

#[test]
fn the_providers_capital_sits_where_the_standards_put_it() {
    let room = room(2);
    let waterfall = four_layers(&room.key, "DeCCP-A");
    let names: Vec<_> = waterfall
        .tranches
        .iter()
        .map(|t| t.name.split_once(':').unwrap().1.to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "defaulter margin",
            "defaulter fund contribution",
            "provider capital",
            "mutualised pool"
        ]
    );
    assert!(waterfall.has_own_capital());
}

#[test]
fn an_unadmitted_provider_is_refused() {
    let room = room(4);
    let h = house("DeCCP-A", b"house-a");
    let stranger = house("DeCCP-B", b"house-b");
    let ctx = CreditCtx::new(Pedersen::new(b"qomm:defmi:v1"), 64);
    let mut registry = ClearingRegistry::new();
    registry
        .admit(
            &ctx,
            &h,
            margined(&ctx, &h.handle),
            four_layers(&room.key, "DeCCP-A"),
        )
        .unwrap();
    let novation = stranger.novate(&room.graph(3, ASSET)).unwrap();
    let attestation = stranger.attest(&novation, b"c");
    assert!(registry
        .check_cycle(&attestation, &novation, &room.parties)
        .unwrap_err()
        .contains("not an admitted provider"));
}

#[test]
fn a_whole_cleared_cycle_checks_out() {
    let room = room(6);
    let h = house("DeCCP-A", b"house-a");
    let ctx = CreditCtx::new(Pedersen::new(b"qomm:defmi:v1"), 64);
    let mut registry = ClearingRegistry::new();
    registry
        .admit(
            &ctx,
            &h,
            margined(&ctx, &h.handle),
            four_layers(&room.key, "DeCCP-A"),
        )
        .unwrap();
    let novation = h.novate(&room.graph(32, ASSET)).unwrap();
    let attestation = h.attest(&novation, b"cycle-1");
    assert_eq!(
        registry.check_cycle(&attestation, &novation, &room.parties),
        Ok(())
    );
}

// --- the other hole that is now closed: two houses, two books -------------

#[test]
fn a_member_cleared_at_two_houses_has_two_positions_and_no_netted_one() {
    let room = room(6);
    let first = house("DeCCP-A", b"house-a");
    let second = house("DeCCP-B", b"house-b");
    let edges = room.graph(10, ASSET);
    let a = first.novate(&edges[..5]).unwrap();
    let b = second.novate(&edges[5..]).unwrap();
    assert_eq!(check_novation(&first.handle, &a), Ok(()));
    assert_eq!(check_novation(&second.handle, &b), Ok(()));

    let at_a = net_positions(&a);
    let at_b = net_positions(&b);
    let both: Vec<_> = at_a.keys().filter(|h| at_b.contains_key(*h)).collect();
    assert!(
        !both.is_empty(),
        "the fixture should put someone at both houses"
    );

    let default = DefaultAcrossProviders {
        member: both[0].to_vec(),
        per_provider: vec![("DeCCP-A".into(), 300), ("DeCCP-B".into(), 700)],
    };
    assert_eq!(default.houses(), 2);
    // the sum, and never the net
    assert_eq!(default.total_shortfall(), 1_000);
    assert_eq!(
        default.netted_shortfall(),
        None,
        "a netted figure across providers is cross-margining, which is \
                an agreement and not an identity"
    );
}

#[test]
fn each_house_resolves_its_own_default_in_its_own_waterfall() {
    let mut rng = OsRng;
    let ctx = CreditCtx::new(Pedersen::new(b"qomm:defmi:v1"), 64);
    let base = Pedersen::new(b"qomm:defmi:v1");
    let mut registry = ClearingRegistry::new();
    for name in ["DeCCP-A", "DeCCP-B"] {
        let handle = name.to_lowercase().into_bytes();
        let h = house(name, &handle);
        registry
            .admit(&ctx, &h, margined(&ctx, &handle), four_layers(&base, name))
            .unwrap();
    }
    assert_eq!(registry.names(), vec!["DeCCP-A", "DeCCP-B"]);

    // the layers are the same shape at both, and the resolutions are separate
    let amounts = [100u64, 200, 400, 5_000];
    let blindings: Vec<Scalar> = amounts.iter().map(|_| Scalar::random(&mut rng)).collect();
    let tranches: Vec<Tranche> = amounts
        .iter()
        .zip(&blindings)
        .enumerate()
        .map(|(i, (a, b))| Tranche {
            name: format!("t{i}"),
            commitment: base.commit_u64(*a, b),
        })
        .collect();
    let waterfall = qomm_defmi::credit::Waterfall::new(base.clone(), tranches, 64);
    let (resolution, drawn) = waterfall
        .build(
            500,
            &Scalar::random(&mut rng),
            &amounts,
            &blindings,
            &mut rng,
        )
        .unwrap();
    assert_eq!(waterfall.check(&resolution, &mut rng), Ok(()));
    // the pool is untouched until the provider's own capital has been eaten
    assert_eq!(drawn, vec![100, 200, 200, 0]);
}

// --- what admitting a provider actually establishes -------------------------

/// The margin a provider is admitted on has to be a margin, and has to be its own.
///
/// `admit` took a `CreditLine` and stored it. It never verified the backing
/// proof and never checked whose handle it was under, so a provider could be
/// admitted on a line built by anybody, over anybody's collateral, proving
/// nothing. The registry then reported it as margined, and the whole point of
/// the entry is that the attestation costs something to get wrong.
#[test]
fn a_provider_is_not_admitted_on_a_margin_that_proves_nothing() {
    let mut rng = OsRng;
    let room = room(4);
    let ctx = CreditCtx::new(room.key.clone(), 64);
    let h = house("DeCCP-A", b"house-a");

    // a line whose backing proof is about other commitments
    let mut forged = margined(&ctx, &h.handle);
    forged.cap_commitment = room.key.commit_u64(1, &Scalar::random(&mut rng));
    let why = ClearingRegistry::new()
        .admit(&ctx, &h, forged, four_layers(&room.key, "DeCCP-A"))
        .unwrap_err();
    assert!(why.contains("backing") || why.contains("cover"), "{why}");
}

#[test]
fn a_provider_is_not_admitted_on_somebody_elses_margin() {
    let room = room(4);
    let ctx = CreditCtx::new(room.key.clone(), 64);
    let h = house("DeCCP-A", b"house-a");
    let someone_else = margined(&ctx, b"a-member-not-the-house");
    let why = ClearingRegistry::new()
        .admit(&ctx, &h, someone_else, four_layers(&room.key, "DeCCP-A"))
        .unwrap_err();
    assert!(why.contains("handle") || why.contains("its own"), "{why}");
}

/// A tranche is the provider's own because the waterfall says which one it is,
/// not because its name has the words in it.
///
/// `has_own_capital` matched any tranche whose name *contained* "provider
/// capital". A name is not a commitment: anybody assembling a waterfall could
/// call a tranche that, and a tranche committing zero passed exactly as well as
/// one holding the capital.
#[test]
fn the_provider_tranche_is_identified_by_position_and_not_by_its_name() {
    let room = room(4);
    let ctx = CreditCtx::new(room.key.clone(), 64);
    let h = house("DeCCP-A", b"house-a");
    let mut named = four_layers(&room.key, "DeCCP-A");
    // rename the real one and give the words to the mutualised pool instead
    named.tranches[named.own].name = "DeCCP-A:something else".into();
    named.tranches[3].name = "DeCCP-A:provider capital".into();
    let before = named.own;
    assert_eq!(before, 2, "the provider's layer is the third of the four");
    assert!(
        ClearingRegistry::new()
            .admit(&ctx, &h, margined(&ctx, &h.handle), named)
            .is_ok(),
        "renaming tranches must not change which one is the provider's"
    );
}
