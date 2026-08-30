use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use qomm_transport::binding::{check_all, check_share, BindingDealer, BoundInputs};
use qomm_transport::roles::{
    audit_node, check_field_width, split, ComputingNode, EntityLimits, EntityRateLimiter,
    InputParty, Refused,
};
use qomm_zk::pedersen::Pedersen;
use qomm_zk::shamir;
use rand_core::OsRng;

fn reconstruct(bound: &BoundInputs, position: usize) -> Result<Scalar, String> {
    let dealt = bound
        .values
        .get(position)
        .ok_or_else(|| format!("no dealt value at position {position}"))?;
    let points = shamir::points(bound.n_parties);
    let shares = (1..=bound.n_parties)
        .map(|party| {
            dealt
                .shares
                .value_shares
                .get(&party)
                .copied()
                .ok_or_else(|| format!("missing share for party {party}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(shamir::reconstruct(&points, &shares))
}

#[test]
fn additive_shares_reconstruct_and_field_width_fails_closed() {
    for value in [0, 1, 100, -50, 1_599_845] {
        let shares = split(value, 7, 32).unwrap();
        assert_eq!(shares.iter().sum::<i128>(), value);
        assert_eq!(shares.len(), 7);
    }
    check_field_width(7, 32, 128).unwrap();
    assert!(check_field_width(7, 32, 64)
        .unwrap_err()
        .to_string()
        .contains("cannot hold"));
}

#[test]
fn signed_dealing_names_a_node_that_substitutes_or_moves_a_share() {
    let signing = SigningKey::generate(&mut OsRng);
    let party = InputParty {
        name: "trader".into(),
        n_nodes: 7,
        value_bits: 32,
        signing_key: Some(signing.clone()),
    };
    let mut nodes = (0..7).map(ComputingNode::new).collect::<Vec<_>>();
    party.deal(&[100, 1, 0], &mut nodes).unwrap();
    assert!(nodes.iter().all(|node| audit_node(
        node,
        "trader",
        &signing.verifying_key(),
        &node.inputs
    )
    .is_empty()));
    let mut changed = nodes[3].inputs.clone();
    changed[1] += 1;
    assert_eq!(
        audit_node(&nodes[3], "trader", &signing.verifying_key(), &changed),
        vec![1]
    );
    let borrowed = ComputingNode {
        index: 3,
        inputs: nodes[4].inputs.clone(),
        receipts: nodes[4].receipts.clone(),
    };
    assert!(!audit_node(
        &borrowed,
        "trader",
        &signing.verifying_key(),
        &borrowed.inputs
    )
    .is_empty());
}

#[test]
fn the_share_consumed_by_the_circuit_is_the_committed_share() {
    let key = Pedersen::new(b"qomm:binding:v1");
    let mut dealer = BindingDealer::new(key.clone(), 7, 2, vec!["qty".into()]).unwrap();
    dealer.deal(20, 0, &mut OsRng).unwrap();
    let bound = dealer.bound();
    assert_eq!(reconstruct(&bound, 0).unwrap(), Scalar::from(20_u64));
    assert!(check_all(&key, &bound).is_empty());
    assert!((1..=7).all(|party| check_share(&bound.values[0], party, &key)));

    let mut tampered = bound.clone();
    *tampered.values[0].shares.value_shares.get_mut(&4).unwrap() += Scalar::ONE;
    assert_eq!(check_all(&key, &tampered), vec![(4, 0)]);
}

#[test]
fn rate_limits_are_keyed_on_the_entity_scope_nullifier_not_wallets() {
    let entity_nullifier = RISTRETTO_BASEPOINT_POINT * Scalar::from(123_u64);
    // Four wallet presentations carry the same entity nullifier.
    let wallets = [entity_nullifier; 4];
    let mut limiter = EntityRateLimiter::new(EntityLimits {
        max_requests: 3,
        max_probe_lots: 10_000,
        max_epsilon: 1.0,
    });
    for wallet in wallets.iter().take(3) {
        limiter.allow_request(wallet, 7, 0).unwrap();
    }
    assert_eq!(
        limiter.allow_request(&wallets[3], 7, 0),
        Err(Refused::RequestCap)
    );
    let other_entity = RISTRETTO_BASEPOINT_POINT * Scalar::from(456_u64);
    limiter.allow_request(&other_entity, 7, 0).unwrap();
}
