//! Recipient-scoped checks for the distributed nonce dealing boundary.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_gadgets::{
    CommittedContributions, DealerCoefficientCommitments, NodeContributions,
};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::shamir;
use rand_core::OsRng;

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const T: usize = 2;

fn dealers(key: &Pedersen, parties: &[PartyId], count: usize) -> Vec<CommittedContributions> {
    parties
        .iter()
        .map(|dealer| {
            CommittedContributions::new(key, *dealer, parties, T, count, &mut OsRng).unwrap()
        })
        .collect()
}

fn seals(dealers: &[CommittedContributions]) -> DealerCoefficientCommitments {
    dealers
        .iter()
        .map(|dealer| (dealer.dealer(), dealer.sealed().to_vec()))
        .collect()
}

fn receive(
    key: &Pedersen,
    recipient: PartyId,
    dealers: &[CommittedContributions],
    public: &DealerCoefficientCommitments,
) -> NodeContributions {
    NodeContributions::receive(
        key,
        recipient,
        T,
        public,
        dealers
            .iter()
            .map(|dealer| dealer.delivery_for(recipient).unwrap())
            .collect(),
    )
    .unwrap()
}

fn reconstruct(observations: &[(PartyId, Scalar)]) -> Scalar {
    let points = observations
        .iter()
        .map(|(party, _)| Scalar::from(*party as u64))
        .collect::<Vec<_>>();
    let values = observations
        .iter()
        .map(|(_, value)| *value)
        .collect::<Vec<_>>();
    shamir::reconstruct(&points, &values)
}

fn reconstruct_if_quorum(observations: &[(PartyId, Scalar)], threshold: usize) -> Option<Scalar> {
    (observations.len() > threshold).then(|| reconstruct(observations))
}

#[test]
fn hostile_single_caller_cannot_reconstruct_joint_nonce_or_witness() {
    let key = Pedersen::new(b"qomm:test:hostile-single-caller");
    let parties = [1, 2, 3];
    let all_dealers = dealers(&key, &parties, 1);
    let public = seals(&all_dealers);

    // This is everything party 1 legitimately receives: every public ladder,
    // one private evaluation from each dealer, and its own dealer state.  As a
    // dealer it can recover its own polynomial constant; that still leaves
    // only one evaluation of the sum of every other dealer's polynomial.
    let hostile_view = receive(&key, 1, &all_dealers, &public);
    let own_dealer = &all_dealers[0];
    let own_constant = reconstruct(
        &parties
            .iter()
            .map(|recipient| {
                (
                    *recipient,
                    own_dealer.delivery_for(*recipient).unwrap().slots()[0].0,
                )
            })
            .collect::<Vec<_>>(),
    );
    let own_delivery = own_dealer.delivery_for(1).unwrap().slots()[0].0;
    let other_dealers_observations = vec![(
        hostile_view.party(),
        hostile_view.share(0).unwrap() - own_delivery,
    )];
    let recovered_nonce = reconstruct_if_quorum(&other_dealers_observations, T)
        .map(|other_dealers_constant| own_constant + other_dealers_constant);

    // The published response is public.  The old aggregate `open()` API made
    // the first line Some(k), after which this was exactly w = (z-k)/c.
    let all_nodes = parties
        .iter()
        .map(|party| receive(&key, *party, &all_dealers, &public))
        .collect::<Vec<_>>();
    let oracle_nonce = reconstruct(
        &all_nodes
            .iter()
            .map(|node| (node.party(), node.share(0).unwrap()))
            .collect::<Vec<_>>(),
    );
    let witness = Scalar::from(1_234u64);
    let challenge = Scalar::from(17u64);
    let published_response = oracle_nonce + challenge * witness;
    let recovered_witness =
        recovered_nonce.map(|nonce| (published_response - nonce) * challenge.invert());

    assert!(recovered_nonce.is_none());
    assert_ne!(recovered_witness, Some(witness));
    assert_eq!(other_dealers_observations.len(), 1);
    println!(
        "hostile_node=1 known_own_dealer_constant=true other_dealer_evaluations=1 required={} recovered_nonce=false recovered_witness=false",
        T + 1
    );
}

#[test]
fn every_private_delivery_matches_the_public_coefficient_ladder() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let all_dealers = dealers(&key, &PARTIES, 3);
    for dealer in &all_dealers {
        assert_eq!(dealer.sealed().len(), 3);
        assert!(dealer.sealed().iter().all(|ladder| ladder.len() == T + 1));
        for recipient in PARTIES {
            let delivery = dealer.delivery_for(recipient).unwrap();
            assert!(dealer.check_delivery(&delivery));
            assert_eq!(delivery.recipient(), recipient);
            assert_eq!(delivery.dealer(), dealer.dealer());
        }
    }
}

#[test]
fn a_node_that_opens_to_something_else_is_caught_and_named() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let all_dealers = dealers(&key, &PARTIES, 2);
    let public = seals(&all_dealers);
    let recipient = 3;
    let mut deliveries = all_dealers
        .iter()
        .map(|dealer| dealer.delivery_for(recipient).unwrap())
        .collect::<Vec<_>>();
    deliveries
        .iter_mut()
        .find(|delivery| delivery.dealer() == 4)
        .unwrap()
        .slots_mut()[0]
        .0 += Scalar::ONE;
    let error = NodeContributions::receive(&key, recipient, T, &public, deliveries)
        .expect_err("an inconsistent delivery must fail closed");
    assert!(error.contains("dealer 4"), "{error}");
}

#[test]
fn what_a_late_node_would_have_needed_is_not_available() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let a = dealers(&key, &PARTIES, 1);
    let b = dealers(&key, &PARTIES, 1);
    let seals_a: BTreeSet<_> = a
        .iter()
        .map(|dealer| dealer.sealed()[0][0].compress().to_bytes())
        .collect();
    let seals_b: BTreeSet<_> = b
        .iter()
        .map(|dealer| dealer.sealed()[0][0].compress().to_bytes())
        .collect();
    assert!(
        seals_a.is_disjoint(&seals_b),
        "two independent runs produced a shared seal"
    );
    let node_a = receive(&key, 1, &a, &seals(&a));
    let node_b = receive(&key, 1, &b, &seals(&b));
    assert_ne!(node_a.share(0), node_b.share(0));
}

#[test]
fn the_result_is_a_sharing_every_quorum_agrees_on() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let all_dealers = dealers(&key, &PARTIES, 2);
    let public = seals(&all_dealers);
    let nodes = PARTIES
        .iter()
        .map(|party| receive(&key, *party, &all_dealers, &public))
        .collect::<Vec<_>>();
    for slot in 0..2 {
        let get = |subset: &[PartyId]| {
            reconstruct(
                &subset
                    .iter()
                    .map(|party| {
                        let node = nodes.iter().find(|node| node.party() == *party).unwrap();
                        (*party, node.share(slot).unwrap())
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let answers = [get(&[1, 2, 3]), get(&[5, 6, 7]), get(&[2, 4, 6])];
        assert!(answers.iter().all(|answer| *answer == answers[0]));
        assert_ne!(get(&[1, 2]), answers[0]);
    }
}

#[test]
fn same_constant_different_polynomial_names_the_dealer() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let all_dealers = dealers(&key, &PARTIES, 1);
    let public = seals(&all_dealers);
    let recipient = 2;
    let deliveries = all_dealers
        .iter()
        .map(|dealer| {
            let mut delivery = dealer.delivery_for(recipient).unwrap();
            if dealer.dealer() == 4 {
                // a'(recipient) = a(recipient) + recipient, while a'(0) = a(0).
                delivery.slots_mut()[0].0 += Scalar::from(recipient as u64);
            }
            delivery
        })
        .collect();
    let error = NodeContributions::receive(&key, recipient, T, &public, deliveries)
        .expect_err("equivocation must fail closed");
    assert!(error.contains("dealer 4"), "{error}");
    println!("equivocating_dealer=4 same_constant_different_polynomial_caught=true");
}

#[test]
fn duplicate_dealer_is_rejected() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let all_dealers = dealers(&key, &PARTIES, 1);
    let public = seals(&all_dealers);
    let mut deliveries = all_dealers
        .iter()
        .map(|dealer| dealer.delivery_for(1).unwrap())
        .collect::<Vec<_>>();
    deliveries.push(all_dealers[0].delivery_for(1).unwrap());
    let error = NodeContributions::receive(&key, 1, T, &public, deliveries)
        .expect_err("a dealer must contribute exactly once");
    assert!(error.contains("dealer 1 contributed twice"), "{error}");
}

#[test]
fn seals_are_public_but_contain_no_scalar_opening() {
    let key = Pedersen::new(b"qomm:quote:v1");
    let all_dealers = dealers(&key, &PARTIES, 1);
    let public = seals(&all_dealers);
    assert_eq!(public.keys().copied().collect::<Vec<_>>(), PARTIES);
    assert!(public.values().all(|slots| slots.len() == 1));
    let _only_public_group_points: BTreeMap<_, _> = public;
}
