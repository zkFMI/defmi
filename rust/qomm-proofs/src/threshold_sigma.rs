//! Threshold assembly for the native `qomm-zk` opening sigma protocol.
//!
//! A sigma response is affine in its witness. Each node therefore forms
//! `z_i = k_i + c w_i` from only its Shamir shares, and a quorum interpolates
//! those responses at zero. First-move commitments interpolate in the exponent.
//! The resulting [`OpeningProof`] is the ordinary `qomm-zk` proof object; its
//! verifier neither knows nor trusts the assembling quorum.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::shamir;
use qomm_zk::sigma::{opening_challenge, OpeningProof};
use rand_core::{CryptoRng, RngCore};

use crate::threshold_gadgets::{joint_scalar_nodes, DealerCoefficientCommitments};

pub type PartyId = usize;
pub type ScalarShares = BTreeMap<PartyId, Scalar>;

fn party_point(party: PartyId) -> Result<Scalar, String> {
    if party == 0 {
        return Err("party identifiers start at one; zero is the Shamir secret".into());
    }
    let party = u64::try_from(party).map_err(|_| "party identifier does not fit u64")?;
    Ok(Scalar::from(party))
}

pub(crate) fn checked_parties(parties: &[PartyId]) -> Result<Vec<Scalar>, String> {
    if parties.is_empty() {
        return Err("at least one party is required".into());
    }
    if parties.iter().copied().collect::<BTreeSet<_>>().len() != parties.len() {
        return Err("party identifiers must be distinct".into());
    }
    parties.iter().map(|party| party_point(*party)).collect()
}

pub(crate) fn share_scalar<R: RngCore + CryptoRng>(
    secret: &Scalar,
    parties: &[PartyId],
    threshold: usize,
    rng: &mut R,
) -> Result<ScalarShares, String> {
    let points = checked_parties(parties)?;
    let shares = shamir::share(secret, threshold, &points, rng);
    Ok(parties.iter().copied().zip(shares).collect())
}

/// Lagrange coefficients that reconstruct a Shamir polynomial at zero.
///
/// The interpolation itself stays in `qomm-zk::shamir`: each coefficient is
/// obtained by reconstructing a unit vector over the requested points.
pub fn lagrange_at_zero(parties: &[PartyId]) -> Result<BTreeMap<PartyId, Scalar>, String> {
    let points = checked_parties(parties)?;
    let mut coefficients = BTreeMap::new();
    for (index, party) in parties.iter().copied().enumerate() {
        let mut basis = vec![Scalar::ZERO; parties.len()];
        basis[index] = Scalar::ONE;
        coefficients.insert(party, shamir::reconstruct(&points, &basis));
    }
    Ok(coefficients)
}

/// A secret and its Pedersen blinding, both degree-`threshold` shared.
///
/// The coefficient commitments are the public VSS ladder used to validate a
/// recipient's share and later attribute a malformed partial response.
#[derive(Clone, Debug)]
pub struct ShareSet {
    pub commitment: RistrettoPoint,
    pub value_shares: ScalarShares,
    pub blinding_shares: ScalarShares,
    pub threshold: usize,
    pub coefficient_commitments: Vec<RistrettoPoint>,
}

/// Deal one verifiable sharing.
pub fn deal<R: RngCore + CryptoRng>(
    key: &Pedersen,
    value: &Scalar,
    blinding: &Scalar,
    parties: &[PartyId],
    threshold: usize,
    rng: &mut R,
) -> Result<ShareSet, String> {
    if parties.len() <= threshold {
        return Err(format!(
            "{} parties cannot support threshold {threshold}; at least {} are required",
            parties.len(),
            threshold + 1
        ));
    }
    let points = checked_parties(parties)?;
    let (value_evaluations, value_coefficients) =
        shamir::share_with_coefficients(value, threshold, &points, rng);
    let (blinding_evaluations, blinding_coefficients) =
        shamir::share_with_coefficients(blinding, threshold, &points, rng);
    let coefficient_commitments = value_coefficients
        .iter()
        .zip(&blinding_coefficients)
        .map(|(value, blinding)| key.commit(value, blinding))
        .collect();
    Ok(ShareSet {
        commitment: key.commit(value, blinding),
        value_shares: parties.iter().copied().zip(value_evaluations).collect(),
        blinding_shares: parties.iter().copied().zip(blinding_evaluations).collect(),
        threshold,
        coefficient_commitments,
    })
}

/// Commitment to one node's share, derived only from the public VSS ladder.
pub fn share_commitment(
    coefficient_commitments: &[RistrettoPoint],
    party: PartyId,
) -> Result<RistrettoPoint, String> {
    let x = party_point(party)?;
    let mut power = Scalar::ONE;
    let mut commitment = RistrettoPoint::identity();
    for coefficient in coefficient_commitments {
        commitment += coefficient * power;
        power *= x;
    }
    Ok(commitment)
}

/// Whether a recipient's two scalars open the share commitment in the ladder.
pub fn verify_share(key: &Pedersen, shares: &ShareSet, party: PartyId) -> bool {
    if shares
        .coefficient_commitments
        .first()
        .is_none_or(|constant| constant.compress() != shares.commitment.compress())
    {
        return false;
    }
    let Some(value) = shares.value_shares.get(&party) else {
        return false;
    };
    let Some(blinding) = shares.blinding_shares.get(&party) else {
        return false;
    };
    let Ok(expected) = share_commitment(&shares.coefficient_commitments, party) else {
        return false;
    };
    key.commit(value, blinding).compress() == expected.compress()
}

/// Random opening nonces dealt as shares after every dealer sealed its
/// contribution.
#[derive(Clone, Debug)]
struct NodeNonce {
    party: PartyId,
    k_share: Scalar,
    rho_share: Scalar,
}

#[derive(Clone, Debug)]
struct JointNonce {
    nodes: Vec<NodeNonce>,
    sealed: DealerCoefficientCommitments,
}

impl JointNonce {
    pub fn new<R: RngCore + CryptoRng>(
        key: &Pedersen,
        parties: &[PartyId],
        threshold: usize,
        rng: &mut R,
    ) -> Result<Self, String> {
        let (contributions, sealed) = joint_scalar_nodes(key, parties, threshold, 2, rng)?;
        let nodes = contributions
            .into_iter()
            .map(|contribution| {
                Ok(NodeNonce {
                    party: contribution.party(),
                    k_share: contribution
                        .share(0)
                        .ok_or("joint nonce omitted its value slot")?,
                    rho_share: contribution
                        .share(1)
                        .ok_or("joint nonce omitted its blinding slot")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { nodes, sealed })
    }

    fn node(&self, party: PartyId) -> Option<&NodeNonce> {
        self.nodes.iter().find(|node| node.party == party)
    }
}

/// One node's first move, `g^k_i h^rho_i`.
fn node_commitment(
    key: &Pedersen,
    nonce: &JointNonce,
    party: PartyId,
) -> Result<RistrettoPoint, String> {
    let node = nonce
        .node(party)
        .ok_or_else(|| format!("missing nonce contribution for party {party}"))?;
    Ok(key.commit(&node.k_share, &node.rho_share))
}

/// Interpolate first moves in the exponent.
pub fn combine_commitments(
    partials: &BTreeMap<PartyId, RistrettoPoint>,
) -> Result<RistrettoPoint, String> {
    let parties: Vec<_> = partials.keys().copied().collect();
    let coefficients = lagrange_at_zero(&parties)?;
    Ok(partials
        .iter()
        .fold(RistrettoPoint::identity(), |sum, (party, partial)| {
            sum + partial * coefficients[party]
        }))
}

fn node_response(
    shares: &ShareSet,
    nonce: &JointNonce,
    party: PartyId,
    challenge: &Scalar,
) -> Result<(Scalar, Scalar), String> {
    let value = shares
        .value_shares
        .get(&party)
        .ok_or_else(|| format!("missing value share for party {party}"))?;
    let blinding = shares
        .blinding_shares
        .get(&party)
        .ok_or_else(|| format!("missing blinding share for party {party}"))?;
    let node = nonce
        .node(party)
        .ok_or_else(|| format!("missing nonce contribution for party {party}"))?;
    Ok((
        node.k_share + challenge * value,
        node.rho_share + challenge * blinding,
    ))
}

pub fn combine_responses(
    partials: &BTreeMap<PartyId, (Scalar, Scalar)>,
) -> Result<(Scalar, Scalar), String> {
    let parties: Vec<_> = partials.keys().copied().collect();
    let coefficients = lagrange_at_zero(&parties)?;
    let mut value = Scalar::ZERO;
    let mut blinding = Scalar::ZERO;
    for (party, (z_value, z_blinding)) in partials {
        value += coefficients[party] * z_value;
        blinding += coefficients[party] * z_blinding;
    }
    Ok((value, blinding))
}

/// Name partial opening responses that do not match the share each node
/// published in the VSS ladder.
pub fn audit_partials(
    key: &Pedersen,
    coefficient_commitments: &[RistrettoPoint],
    quorum: &[PartyId],
    partial_commitments: &BTreeMap<PartyId, RistrettoPoint>,
    partial_responses: &BTreeMap<PartyId, (Scalar, Scalar)>,
    challenge: &Scalar,
) -> Vec<PartyId> {
    quorum
        .iter()
        .copied()
        .filter(|party| {
            let (Some(t), Some((z_value, z_blinding)), Ok(expected)) = (
                partial_commitments.get(party),
                partial_responses.get(party),
                share_commitment(coefficient_commitments, *party),
            ) else {
                return true;
            };
            key.commit(z_value, z_blinding).compress() != (t + expected * challenge).compress()
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct OpeningAssemblyTranscript {
    pub quorum: Vec<PartyId>,
    pub partial_commitments: BTreeMap<PartyId, RistrettoPoint>,
    pub partial_responses: BTreeMap<PartyId, (Scalar, Scalar)>,
    pub challenge: Scalar,
    pub bad_partials: Vec<PartyId>,
    pub nonce_seals: DealerCoefficientCommitments,
}

/// One node's input to an opening response.  It contains exactly one Shamir
/// evaluation of the value and its blinding.
#[derive(Clone, Debug)]
pub struct OpeningNodeContribution {
    party: PartyId,
    value_share: Scalar,
    blinding_share: Scalar,
}

impl OpeningNodeContribution {
    pub fn new(party: PartyId, value_share: Scalar, blinding_share: Scalar) -> Self {
        Self {
            party,
            value_share,
            blinding_share,
        }
    }

    pub fn party(&self) -> PartyId {
        self.party
    }
}

/// Assemble an ordinary opening proof and retain enough public data to name a
/// malformed partial.
pub fn joint_prove_opening<R: RngCore + CryptoRng>(
    key: &Pedersen,
    shares: &ShareSet,
    quorum: &[PartyId],
    transcript: &mut Transcript,
    faulty: Option<&BTreeMap<PartyId, (Scalar, Scalar)>>,
    rng: &mut R,
) -> Result<(OpeningProof, OpeningAssemblyTranscript), String> {
    let nonce = JointNonce::new(key, quorum, shares.threshold, rng)?;
    let partial_commitments = quorum
        .iter()
        .map(|party| Ok((*party, node_commitment(key, &nonce, *party)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let t = combine_commitments(&partial_commitments)?;
    let challenge = opening_challenge(transcript, &shares.commitment, &t);
    let mut partial_responses = quorum
        .iter()
        .map(|party| Ok((*party, node_response(shares, &nonce, *party, &challenge)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    for (party, replacement) in faulty.into_iter().flatten() {
        if partial_responses.contains_key(party) {
            partial_responses.insert(*party, *replacement);
        }
    }
    let (z_value, z_blinding) = combine_responses(&partial_responses)?;
    let bad_partials = audit_partials(
        key,
        &shares.coefficient_commitments,
        quorum,
        &partial_commitments,
        &partial_responses,
        &challenge,
    );
    Ok((
        OpeningProof {
            t,
            z_value,
            z_blinding,
        },
        OpeningAssemblyTranscript {
            quorum: quorum.to_vec(),
            partial_commitments,
            partial_responses,
            challenge,
            bad_partials,
            nonce_seals: nonce.sealed,
        },
    ))
}

/// Assemble an opening when the enclosing circuit already carries shares and
/// no separate VSS ladder is available. This is the range-linkage and winner
/// opening primitive; it still emits an ordinary [`OpeningProof`].
#[allow(clippy::too_many_arguments)]
pub fn joint_opening_from_shares<R: RngCore + CryptoRng>(
    key: &Pedersen,
    commitment: &RistrettoPoint,
    value_shares: &ScalarShares,
    blinding_shares: &ScalarShares,
    threshold: usize,
    quorum: &[PartyId],
    transcript: &mut Transcript,
    rng: &mut R,
) -> Result<(OpeningProof, OpeningAssemblyTranscript), String> {
    let shares = ShareSet {
        commitment: *commitment,
        value_shares: value_shares.clone(),
        blinding_shares: blinding_shares.clone(),
        threshold,
        coefficient_commitments: Vec::new(),
    };
    let nonce = JointNonce::new(key, quorum, threshold, rng)?;
    let partial_commitments = quorum
        .iter()
        .map(|party| Ok((*party, node_commitment(key, &nonce, *party)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let t = combine_commitments(&partial_commitments)?;
    let challenge = opening_challenge(transcript, commitment, &t);
    let partial_responses = quorum
        .iter()
        .map(|party| Ok((*party, node_response(&shares, &nonce, *party, &challenge)?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let (z_value, z_blinding) = combine_responses(&partial_responses)?;
    Ok((
        OpeningProof {
            t,
            z_value,
            z_blinding,
        },
        OpeningAssemblyTranscript {
            quorum: quorum.to_vec(),
            partial_commitments,
            partial_responses,
            challenge,
            bad_partials: Vec::new(),
            nonce_seals: nonce.sealed,
        },
    ))
}

/// Assemble an ordinary opening proof from independently produced per-node
/// contributions.  No map containing a quorum of private evaluations is ever
/// accepted or constructed.
#[allow(clippy::too_many_arguments)]
pub fn joint_opening_from_contributions<R: RngCore + CryptoRng>(
    key: &Pedersen,
    commitment: &RistrettoPoint,
    contributions: &[OpeningNodeContribution],
    threshold: usize,
    quorum: &[PartyId],
    transcript: &mut Transcript,
    rng: &mut R,
) -> Result<(OpeningProof, OpeningAssemblyTranscript), String> {
    if contributions.len() != quorum.len() {
        return Err(format!(
            "received {} opening contributions for a quorum of {}",
            contributions.len(),
            quorum.len()
        ));
    }
    let by_party = contributions
        .iter()
        .map(|contribution| (contribution.party, contribution))
        .collect::<BTreeMap<_, _>>();
    if by_party.len() != contributions.len()
        || quorum.iter().any(|party| !by_party.contains_key(party))
    {
        return Err("opening contributions do not exactly match the quorum".into());
    }
    let (nonce_nodes, nonce_seals) = joint_scalar_nodes(key, quorum, threshold, 2, rng)?;
    let partial_commitments = nonce_nodes
        .iter()
        .map(|nonce| {
            let k = nonce
                .share(0)
                .ok_or("opening nonce omitted its value slot")?;
            let rho = nonce
                .share(1)
                .ok_or("opening nonce omitted its blinding slot")?;
            Ok((nonce.party(), key.commit(&k, &rho)))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let t = combine_commitments(&partial_commitments)?;
    let challenge = opening_challenge(transcript, commitment, &t);
    let partial_responses = nonce_nodes
        .iter()
        .map(|nonce| {
            let node = by_party[&nonce.party()];
            let k = nonce
                .share(0)
                .ok_or("opening nonce omitted its value slot")?;
            let rho = nonce
                .share(1)
                .ok_or("opening nonce omitted its blinding slot")?;
            Ok((
                nonce.party(),
                (
                    k + challenge * node.value_share,
                    rho + challenge * node.blinding_share,
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let (z_value, z_blinding) = combine_responses(&partial_responses)?;
    Ok((
        OpeningProof {
            t,
            z_value,
            z_blinding,
        },
        OpeningAssemblyTranscript {
            quorum: quorum.to_vec(),
            partial_commitments,
            partial_responses,
            challenge,
            bad_partials: Vec::new(),
            nonce_seals,
        },
    ))
}
