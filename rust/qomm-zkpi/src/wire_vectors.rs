//! Vectors another implementation can check itself against.
//!
//! Two implementations that agree on a table and disagree on a byte have not
//! interoperated, and the only thing that finds that out is fixed bytes.
//!
//! The positives are generated once and written to disk; checking reads them
//! back and requires that decoding and re-encoding produces **the same bytes**.
//! That is a stronger statement than "it parsed", and it needs no deterministic
//! randomness --- the artefact on disk is the fixed point, not the generator.
//!
//! The negatives are derived from a positive by mutation, because the failures
//! worth pinning are the ones a second implementation is most likely to get
//! wrong: the wrong magic, a version it does not know, a truncated body, a byte
//! left over, and a commitment that is not a group element.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use frost_ristretto255 as frost;
use qomm_proofs::threshold_range::{deal_bits, joint_prove_range_from_contributions};
use qomm_proofs::threshold_sigma::PartyId;
use qomm_zk::pedersen::Pedersen;
use rand_core::OsRng;

use crate::wire::{decode, encode, fingerprint, MAGIC, VERSION};
use crate::{
    deal_quorum, Bounds, Instruction, Issuer, PartialInstruction, AMOUNT_RANGE_CONTEXT,
    PRICE_RANGE_CONTEXT,
};

const PARTIES: [PartyId; 7] = [1, 2, 3, 4, 5, 6, 7];
const QUORUM: [PartyId; 3] = [1, 2, 3];

pub struct Vector {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub accepts: bool,
    pub why: &'static str,
}

/// One signed instruction, issued the way a quorum issues one.
pub fn sample() -> Instruction {
    sample_with_quorum().0
}

/// The same, with the public key package a venue would check it against.
pub fn sample_with_quorum() -> (Instruction, frost::keys::PublicKeyPackage) {
    let mut rng = OsRng;
    let (secret, public) = deal_quorum(7, 3, &mut rng).expect("deal");
    let shares: BTreeMap<_, _> = secret
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let issuer = Issuer::new(Pedersen::new(b"qomm:defmi:v1"), Bounds::default());
    let (digest, _openings, partial) = issuer
        .build(
            1_000,
            99_500,
            3,
            RistrettoPoint::mul_base(&Scalar::from(11u64)),
            RistrettoPoint::mul_base(&Scalar::from(12u64)),
            1_800_000_000,
            [7u8; 32],
            1_599_845,
            &mut rng,
        )
        .expect("issue");

    let chosen: Vec<_> = shares.keys().take(3).cloned().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (nonce, commitment) = frost::round1::commit(shares[id].signing_share(), &mut rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, &digest);
    let mut signature_shares = BTreeMap::new();
    for id in &chosen {
        signature_shares.insert(
            *id,
            frost::round2::sign(&package, &nonces[id], &shares[id]).expect("sign"),
        );
    }
    let signature = frost::aggregate(&package, &signature_shares, &public).expect("aggregate");
    (partial.sealed(signature), public)
}

/// A signed version-2 instruction with range proofs assembled from node-local
/// Shamir contributions. This is the product-format self-test and vector source;
/// the returned bounds are part of the verifier configuration, not the wire.
pub fn production_sample_with_quorum() -> (Instruction, frost::keys::PublicKeyPackage, Bounds) {
    let mut rng = OsRng;
    let key = Pedersen::new(b"qomm:defmi:v1");
    let bounds = Bounds {
        amount_bits: 16,
        price_bits: 32,
        ..Bounds::default()
    };
    let amount = deal_bits(
        &key,
        1_000,
        &Scalar::random(&mut rng),
        bounds.amount_bits,
        &PARTIES,
        2,
        &mut rng,
    )
    .expect("deal amount bits");
    let price = deal_bits(
        &key,
        99_990,
        &Scalar::random(&mut rng),
        bounds.price_bits,
        &PARTIES,
        2,
        &mut rng,
    )
    .expect("deal price bits");
    let amount_nodes = QUORUM
        .iter()
        .map(|party| {
            amount
                .node_contribution(*party)
                .expect("amount contribution")
        })
        .collect::<Vec<_>>();
    let price_nodes = QUORUM
        .iter()
        .map(|party| price.node_contribution(*party).expect("price contribution"))
        .collect::<Vec<_>>();
    let (amount_range, _) = joint_prove_range_from_contributions(
        &key,
        &amount_nodes,
        &QUORUM,
        AMOUNT_RANGE_CONTEXT,
        &mut rng,
    )
    .expect("assemble amount range proof");
    let (price_range, _) = joint_prove_range_from_contributions(
        &key,
        &price_nodes,
        &QUORUM,
        PRICE_RANGE_CONTEXT,
        &mut rng,
    )
    .expect("assemble price range proof");
    let partial = PartialInstruction::from_threshold_ranges(
        &key,
        &bounds,
        amount.commitment,
        price.commitment,
        key.commit(&Scalar::from(3u64), &Scalar::random(&mut rng)),
        amount_range,
        price_range,
        RistrettoPoint::mul_base(&Scalar::from(11u64)),
        RistrettoPoint::mul_base(&Scalar::from(12u64)),
        1_800_000_000,
        [9u8; 32],
        [42u8; 32],
    )
    .expect("build product instruction");
    let digest = partial.digest().to_vec();
    let (secret, public) = deal_quorum(7, 3, &mut rng).expect("deal FROST quorum");
    let shares: BTreeMap<_, _> = secret
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let chosen: Vec<_> = shares.keys().take(3).copied().collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &chosen {
        let (nonce, commitment) = frost::round1::commit(shares[id].signing_share(), &mut rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, &digest);
    let signature_shares = chosen
        .iter()
        .map(|id| {
            (
                *id,
                frost::round2::sign(&package, &nonces[id], &shares[id])
                    .expect("sign product vector"),
            )
        })
        .collect();
    let signature = frost::aggregate(&package, &signature_shares, &public)
        .expect("aggregate product vector signature");
    (partial.sealed(signature), public, bounds)
}

fn tagged(name: &'static str, bytes: Vec<u8>, accepts: bool, why: &'static str) -> Vector {
    let digest = fingerprint(&bytes);
    Vector {
        name,
        bytes,
        digest,
        accepts,
        why,
    }
}

/// One fresh positive and the five negatives derived from it.
pub fn build() -> Vec<Vector> {
    let good = encode(&sample());
    let mut out = vec![tagged(
        "accepted",
        good.clone(),
        true,
        "a signed instruction, as issued",
    )];

    let mut wrong_magic = good.clone();
    wrong_magic[0] = b'X';
    out.push(tagged(
        "wrong-magic",
        wrong_magic,
        false,
        "does not begin QOMMZKPI",
    ));

    let mut future = good.clone();
    future[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&(VERSION + 1).to_be_bytes());
    out.push(tagged(
        "unknown-version",
        future,
        false,
        "a version this build does not know --- refused, not guessed at",
    ));

    out.push(tagged(
        "truncated",
        good[..good.len() - 1].to_vec(),
        false,
        "one byte short, which is not a shorter instruction",
    ));

    let mut trailing = good.clone();
    trailing.push(0);
    out.push(tagged(
        "trailing-byte",
        trailing,
        false,
        "one byte over, so it is a different message",
    ));

    let mut not_a_point = good.clone();
    // the first commitment starts right after magic and version, and 0xff...ff
    // is not a canonical Ristretto encoding
    for byte in not_a_point[MAGIC.len() + 2..MAGIC.len() + 34].iter_mut() {
        *byte = 0xff;
    }
    out.push(tagged(
        "not-a-point",
        not_a_point,
        false,
        "a commitment that is not a group element",
    ));

    let product = encode(&production_sample_with_quorum().0);
    out.push(tagged(
        "accepted-v2",
        product.clone(),
        true,
        "a signed version-2 instruction with jointly assembled range proofs",
    ));

    let mut wrong_magic = product.clone();
    wrong_magic[0] = b'X';
    out.push(tagged(
        "wrong-magic-v2",
        wrong_magic,
        false,
        "does not begin QOMMZKPI",
    ));

    let mut future = product.clone();
    future[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&(VERSION + 1).to_be_bytes());
    out.push(tagged(
        "unknown-version-v2",
        future,
        false,
        "a version this build does not know --- refused, not guessed at",
    ));

    out.push(tagged(
        "truncated-v2",
        product[..product.len() - 1].to_vec(),
        false,
        "one byte short, which is not a shorter instruction",
    ));

    let mut trailing = product.clone();
    trailing.push(0);
    out.push(tagged(
        "trailing-byte-v2",
        trailing,
        false,
        "one byte over, so it is a different message",
    ));

    let mut not_a_point = product;
    for byte in not_a_point[MAGIC.len() + 2..MAGIC.len() + 34].iter_mut() {
        *byte = 0xff;
    }
    out.push(tagged(
        "not-a-point-v2",
        not_a_point,
        false,
        "a commitment that is not a group element",
    ));

    out
}

/// Read the positives back and require the codec to be a fixed point on them.
///
/// Round-tripping to the *same bytes* is the check. "It parsed" would pass for
/// an implementation that dropped a field and re-derived it.
pub fn check(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let instruction = decode(bytes).map_err(|why| why.to_string())?;
    let again = encode(&instruction);
    if again != bytes {
        return Err(format!(
            "re-encoding gave {} bytes against {} --- the codec is \
                            not a fixed point, so two implementations would \
                            disagree about what they read",
            again.len(),
            bytes.len()
        ));
    }
    Ok(again)
}
