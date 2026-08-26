//! Shared linear wires and jointly assembled product proofs.
//!
//! Pedersen commitments and Shamir shares are both linear, so addition,
//! subtraction, scaling, public shifts, and negation never open a wire. Products
//! are supplied by the MPC and proved with the native `qomm-zk` product sigma
//! protocol, whose responses interpolate. Every nonce contribution is sealed
//! before the dealing round is opened.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::shamir;
use qomm_zk::sigma::{product_challenge, verify_product, ProductProof};
use rand_core::{CryptoRng, RngCore};

use crate::threshold_sigma::{
    checked_parties, combine_commitments, lagrange_at_zero, share_commitment, PartyId, ScalarShares,
};

/// Public Pedersen-VSS ladders, grouped by dealer and scalar slot.
pub type DealerCoefficientCommitments = BTreeMap<PartyId, Vec<Vec<RistrettoPoint>>>;

/// One committed scalar carried only as degree-`t` shares.
#[derive(Clone, Debug)]
pub struct Shared {
    pub commitment: RistrettoPoint,
    pub value: ScalarShares,
    pub blinding: ScalarShares,
    pub coefficient_commitments: Vec<RistrettoPoint>,
}

impl Shared {
    pub fn parties(&self) -> Vec<PartyId> {
        self.value.keys().copied().collect()
    }

    pub fn node_share(&self, party: PartyId) -> Option<NodeShared> {
        Some(NodeShared::new(
            party,
            self.commitment,
            *self.value.get(&party)?,
            *self.blinding.get(&party)?,
            self.coefficient_commitments.clone(),
        ))
    }
}

/// One node's material for one committed wire.  There is no recipient map and
/// therefore no API by which this value can expose another node's evaluation.
#[derive(Clone, Debug)]
pub struct NodeShared {
    party: PartyId,
    commitment: RistrettoPoint,
    value_share: Scalar,
    blinding_share: Scalar,
    coefficient_commitments: Vec<RistrettoPoint>,
}

impl NodeShared {
    pub fn new(
        party: PartyId,
        commitment: RistrettoPoint,
        value_share: Scalar,
        blinding_share: Scalar,
        coefficient_commitments: Vec<RistrettoPoint>,
    ) -> Self {
        Self {
            party,
            commitment,
            value_share,
            blinding_share,
            coefficient_commitments,
        }
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn commitment(&self) -> RistrettoPoint {
        self.commitment
    }

    pub fn coefficient_commitments(&self) -> &[RistrettoPoint] {
        &self.coefficient_commitments
    }

    pub fn own_evaluation(&self) -> (Scalar, Scalar) {
        (self.value_share, self.blinding_share)
    }

    pub(crate) fn shifted(&self, key: &Pedersen, constant: &Scalar) -> Self {
        let mut coefficient_commitments = self.coefficient_commitments.clone();
        if let Some(constant_commitment) = coefficient_commitments.first_mut() {
            *constant_commitment += key.g * constant;
        }
        Self {
            party: self.party,
            commitment: self.commitment + key.g * constant,
            value_share: self.value_share + constant,
            blinding_share: self.blinding_share,
            coefficient_commitments,
        }
    }
}

/// One node's input to a product proof round.  The assembler receives a
/// collection of these independently produced values rather than any share map.
#[derive(Clone, Debug)]
pub struct ProductNodeContribution {
    factor: NodeShared,
    cross_share: Scalar,
}

impl ProductNodeContribution {
    pub fn new(factor: NodeShared, cross_share: Scalar) -> Self {
        Self {
            factor,
            cross_share,
        }
    }

    pub fn party(&self) -> PartyId {
        self.factor.party
    }
}

fn same_shape(a: &Shared, b: &Shared) -> Result<(), String> {
    if a.value.keys().ne(b.value.keys()) || a.blinding.keys().ne(b.blinding.keys()) {
        return Err("shared wires have different party sets".into());
    }
    if a.coefficient_commitments.len() != b.coefficient_commitments.len() {
        return Err("shared wires have different VSS ladder lengths".into());
    }
    Ok(())
}

pub fn add(a: &Shared, b: &Shared) -> Result<Shared, String> {
    same_shape(a, b)?;
    Ok(Shared {
        commitment: a.commitment + b.commitment,
        value: a
            .value
            .iter()
            .map(|(party, value)| (*party, value + b.value[party]))
            .collect(),
        blinding: a
            .blinding
            .iter()
            .map(|(party, value)| (*party, value + b.blinding[party]))
            .collect(),
        coefficient_commitments: a
            .coefficient_commitments
            .iter()
            .zip(&b.coefficient_commitments)
            .map(|(a, b)| a + b)
            .collect(),
    })
}

pub fn sub(a: &Shared, b: &Shared) -> Result<Shared, String> {
    same_shape(a, b)?;
    Ok(Shared {
        commitment: a.commitment - b.commitment,
        value: a
            .value
            .iter()
            .map(|(party, value)| (*party, value - b.value[party]))
            .collect(),
        blinding: a
            .blinding
            .iter()
            .map(|(party, value)| (*party, value - b.blinding[party]))
            .collect(),
        coefficient_commitments: a
            .coefficient_commitments
            .iter()
            .zip(&b.coefficient_commitments)
            .map(|(a, b)| a - b)
            .collect(),
    })
}

pub fn scale(a: &Shared, factor: &Scalar) -> Shared {
    Shared {
        commitment: a.commitment * factor,
        value: a
            .value
            .iter()
            .map(|(party, value)| (*party, value * factor))
            .collect(),
        blinding: a
            .blinding
            .iter()
            .map(|(party, value)| (*party, value * factor))
            .collect(),
        coefficient_commitments: a
            .coefficient_commitments
            .iter()
            .map(|point| point * factor)
            .collect(),
    }
}

/// Add a public constant to a shared wire.
///
/// Adding it to every evaluation changes only the polynomial's constant term,
/// because the Lagrange coefficients at zero sum to one.
pub fn shift(key: &Pedersen, a: &Shared, constant: &Scalar) -> Shared {
    let mut coefficient_commitments = a.coefficient_commitments.clone();
    if let Some(constant_commitment) = coefficient_commitments.first_mut() {
        *constant_commitment += key.g * constant;
    }
    Shared {
        commitment: a.commitment + key.g * constant,
        value: a
            .value
            .iter()
            .map(|(party, value)| (*party, value + constant))
            .collect(),
        blinding: a.blinding.clone(),
        coefficient_commitments,
    }
}

pub fn negate(a: &Shared) -> Shared {
    scale(a, &-Scalar::ONE)
}

/// Compute `g^v h^r` from only a quorum's shares, interpolating in the exponent.
pub fn commitment_from_shares(
    key: &Pedersen,
    value: &ScalarShares,
    blinding: &ScalarShares,
    quorum: &[PartyId],
) -> Result<RistrettoPoint, String> {
    let partials = quorum
        .iter()
        .map(|party| {
            let value = value
                .get(party)
                .ok_or_else(|| format!("missing value share for party {party}"))?;
            let blinding = blinding
                .get(party)
                .ok_or_else(|| format!("missing blinding share for party {party}"))?;
            Ok((*party, key.commit(value, blinding)))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    combine_commitments(&partials)
}

/// Interpolate the coefficient ladder of a public group-valued polynomial.
///
/// Only points are combined: no scalar share or polynomial constant is
/// reconstructed.  Every supplied evaluation is checked against the resulting
/// degree-`threshold` ladder, so an equivocated evaluation is rejected.
pub fn coefficient_commitments_from_evaluations(
    evaluations: &BTreeMap<PartyId, RistrettoPoint>,
    threshold: usize,
) -> Result<Vec<RistrettoPoint>, String> {
    if evaluations.len() < threshold + 1 {
        return Err(format!(
            "{} public evaluations cannot define degree {threshold}",
            evaluations.len()
        ));
    }
    let selected_parties = evaluations
        .keys()
        .copied()
        .take(threshold + 1)
        .collect::<Vec<_>>();
    let selected_points = checked_parties(&selected_parties)?;
    let mut ladder = vec![RistrettoPoint::default(); threshold + 1];
    for (index, party) in selected_parties.iter().enumerate() {
        let x = selected_points[index];
        let mut basis = vec![Scalar::ONE];
        let mut denominator = Scalar::ONE;
        for (other_index, other) in selected_points.iter().enumerate() {
            if other_index == index {
                continue;
            }
            let mut product = vec![Scalar::ZERO; basis.len() + 1];
            for (degree, coefficient) in basis.iter().enumerate() {
                product[degree] -= other * coefficient;
                product[degree + 1] += coefficient;
            }
            basis = product;
            denominator *= x - other;
        }
        let scale = denominator.invert();
        for (degree, coefficient) in basis.iter().enumerate() {
            ladder[degree] += evaluations[party] * (coefficient * scale);
        }
    }
    for (party, point) in evaluations {
        let expected = share_commitment(&ladder, *party)?;
        if expected.compress() != point.compress() {
            return Err(format!(
                "public evaluation for party {party} is inconsistent with a degree-{threshold} coefficient ladder"
            ));
        }
    }
    Ok(ladder)
}

/// One dealer's private delivery to exactly one recipient.
///
/// There is deliberately no map keyed by recipient here: a node can receive
/// this value without gaining a handle to anyone else's evaluation.
#[derive(Clone, Debug)]
pub struct PrivateContribution {
    dealer: PartyId,
    recipient: PartyId,
    slots: Vec<(Scalar, Scalar)>,
}

impl PrivateContribution {
    pub fn dealer(&self) -> PartyId {
        self.dealer
    }

    pub fn recipient(&self) -> PartyId {
        self.recipient
    }

    pub fn slots(&self) -> &[(Scalar, Scalar)] {
        &self.slots
    }

    /// Mutable transport payload used by a dealer (and by attribution tests).
    /// It still contains only this recipient's delivery.
    pub fn slots_mut(&mut self) -> &mut [(Scalar, Scalar)] {
        &mut self.slots
    }
}

/// One dealer's committed VSS contribution.
///
/// Unlike the old aggregate, this value contains only one dealer's polynomial
/// evaluations.  It has no `open` operation and cannot return a map containing
/// a quorum's evaluations.  Each delivery is typed for one recipient.
#[derive(Clone, Debug)]
pub struct CommittedContributions {
    key: Pedersen,
    dealer: PartyId,
    parties: Vec<PartyId>,
    threshold: usize,
    count: usize,
    deliveries: BTreeMap<PartyId, Vec<(Scalar, Scalar)>>,
    sealed: Vec<Vec<RistrettoPoint>>,
}

impl CommittedContributions {
    pub fn new<R: RngCore + CryptoRng>(
        key: &Pedersen,
        dealer: PartyId,
        parties: &[PartyId],
        threshold: usize,
        count: usize,
        rng: &mut R,
    ) -> Result<Self, String> {
        if !parties.contains(&dealer) {
            return Err(format!("dealer {dealer} is outside the party set"));
        }
        let points = checked_parties(parties)?;
        let mut deliveries = parties
            .iter()
            .map(|recipient| (*recipient, Vec::with_capacity(count)))
            .collect::<BTreeMap<_, _>>();
        let mut sealed = Vec::with_capacity(count);
        for _ in 0..count {
            let constant = Scalar::random(&mut *rng);
            let blinding_constant = Scalar::random(&mut *rng);
            let (evaluations, value_coefficients) =
                shamir::share_with_coefficients(&constant, threshold, &points, &mut *rng);
            let (blinding_evaluations, blinding_coefficients) =
                shamir::share_with_coefficients(&blinding_constant, threshold, &points, &mut *rng);
            sealed.push(
                value_coefficients
                    .iter()
                    .zip(&blinding_coefficients)
                    .map(|(value, blinding)| key.commit(value, blinding))
                    .collect(),
            );
            for ((recipient, value), blinding) in parties
                .iter()
                .copied()
                .zip(evaluations)
                .zip(blinding_evaluations)
            {
                deliveries
                    .get_mut(&recipient)
                    .expect("recipient map was initialized from parties")
                    .push((value, blinding));
            }
        }
        Ok(Self {
            key: key.clone(),
            dealer,
            parties: parties.to_vec(),
            threshold,
            count,
            deliveries,
            sealed,
        })
    }

    pub fn dealer(&self) -> PartyId {
        self.dealer
    }

    pub fn sealed(&self) -> &[Vec<RistrettoPoint>] {
        &self.sealed
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Produce only the delivery addressed to `recipient`.
    pub fn delivery_for(&self, recipient: PartyId) -> Option<PrivateContribution> {
        Some(PrivateContribution {
            dealer: self.dealer,
            recipient,
            slots: self.deliveries.get(&recipient)?.clone(),
        })
    }

    pub fn check_delivery(&self, delivery: &PrivateContribution) -> bool {
        if delivery.dealer != self.dealer
            || delivery.slots.len() != self.count
            || !self.parties.contains(&delivery.recipient)
            || self.sealed.len() != self.count
            || self
                .sealed
                .iter()
                .any(|ladder| ladder.len() != self.threshold + 1)
        {
            return false;
        }
        delivery
            .slots
            .iter()
            .zip(&self.sealed)
            .all(|((value, blinding), ladder)| {
                let Ok(expected) = share_commitment(ladder, delivery.recipient) else {
                    return false;
                };
                self.key.commit(value, blinding).compress() == expected.compress()
            })
    }
}

/// Everything one recipient obtains after all dealer seals are fixed.
///
/// This type owns one evaluation per slot, never a `PartyId -> Scalar` map.
#[derive(Clone, Debug)]
pub struct NodeContributions {
    party: PartyId,
    shares: Vec<Scalar>,
    blinding_shares: Vec<Scalar>,
}

impl NodeContributions {
    pub fn receive(
        key: &Pedersen,
        party: PartyId,
        threshold: usize,
        seals: &DealerCoefficientCommitments,
        deliveries: Vec<PrivateContribution>,
    ) -> Result<Self, String> {
        if deliveries.is_empty() {
            return Err(format!("party {party} received no dealer contributions"));
        }
        let count = deliveries[0].slots.len();
        if count == 0 {
            return Err("a contribution must contain at least one slot".into());
        }
        let mut seen = BTreeMap::new();
        let mut shares = vec![Scalar::ZERO; count];
        let mut blinding_shares = vec![Scalar::ZERO; count];
        for delivery in deliveries {
            if delivery.recipient != party {
                return Err(format!(
                    "dealer {} addressed its contribution to party {}, not party {party}",
                    delivery.dealer, delivery.recipient
                ));
            }
            if seen.insert(delivery.dealer, ()).is_some() {
                return Err(format!("dealer {} contributed twice", delivery.dealer));
            }
            let ladders = seals
                .get(&delivery.dealer)
                .ok_or_else(|| format!("dealer {} supplied no prior seal", delivery.dealer))?;
            if delivery.slots.len() != count
                || ladders.len() != count
                || ladders.iter().any(|ladder| ladder.len() != threshold + 1)
            {
                return Err(format!(
                    "dealer {} supplied a malformed contribution",
                    delivery.dealer
                ));
            }
            for (slot, ((value, blinding), ladder)) in
                delivery.slots.iter().zip(ladders).enumerate()
            {
                let expected = share_commitment(ladder, party)?;
                if key.commit(value, blinding).compress() != expected.compress() {
                    return Err(format!(
                        "dealer {} sent an inconsistent share to party {party} in slot {slot}",
                        delivery.dealer
                    ));
                }
                shares[slot] += value;
                blinding_shares[slot] += blinding;
            }
        }
        if seen.len() != seals.len() {
            return Err(format!(
                "party {party} received {} of {} sealed dealer contributions",
                seen.len(),
                seals.len()
            ));
        }
        Ok(Self {
            party,
            shares,
            blinding_shares,
        })
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn count(&self) -> usize {
        self.shares.len()
    }

    pub fn share(&self, slot: usize) -> Option<Scalar> {
        self.shares.get(slot).copied()
    }

    pub fn blinding_share(&self, slot: usize) -> Option<Scalar> {
        self.blinding_shares.get(slot).copied()
    }
}

/// Create one recipient-scoped nonce view per node.  This helper models the
/// transport only; it never builds a map of recipient scalar evaluations.
pub(crate) fn joint_scalar_nodes<R: RngCore + CryptoRng>(
    key: &Pedersen,
    parties: &[PartyId],
    threshold: usize,
    count: usize,
    rng: &mut R,
) -> Result<(Vec<NodeContributions>, DealerCoefficientCommitments), String> {
    let dealers = parties
        .iter()
        .map(|dealer| CommittedContributions::new(key, *dealer, parties, threshold, count, rng))
        .collect::<Result<Vec<_>, _>>()?;
    // Collect every public seal before asking any dealer for a delivery.
    let seals = dealers
        .iter()
        .map(|dealer| (dealer.dealer(), dealer.sealed().to_vec()))
        .collect::<DealerCoefficientCommitments>();
    let nodes = parties
        .iter()
        .map(|recipient| {
            let deliveries = dealers
                .iter()
                .map(|dealer| {
                    dealer.delivery_for(*recipient).ok_or_else(|| {
                        format!(
                            "dealer {} omitted party {recipient}'s contribution",
                            dealer.dealer()
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            NodeContributions::receive(key, *recipient, threshold, &seals, deliveries)
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((nodes, seals))
}

/// Everything needed to attribute one product proof's partial responses.
#[derive(Clone, Debug)]
pub struct ProductAssemblyTranscript {
    pub quorum: Vec<PartyId>,
    pub challenge: Scalar,
    pub c_a: RistrettoPoint,
    pub factor_parts: BTreeMap<PartyId, RistrettoPoint>,
    pub product_parts: BTreeMap<PartyId, RistrettoPoint>,
    pub answers: BTreeMap<PartyId, (Scalar, Scalar, Scalar)>,
    /// Factor VSS ladder published before the challenge.
    pub share_coefficient_commitments: Vec<RistrettoPoint>,
    /// Product-relation ladder published before the challenge.
    pub cross_coefficient_commitments: Vec<RistrettoPoint>,
    pub nonce_seals: DealerCoefficientCommitments,
}

impl ProductAssemblyTranscript {
    /// Reassemble after transporting or auditing the per-node answers.
    pub fn assemble(&self) -> Result<ProductProof, String> {
        let coefficients = lagrange_at_zero(&self.quorum)?;
        let mut z_b = Scalar::ZERO;
        let mut z_rb = Scalar::ZERO;
        let mut z_s = Scalar::ZERO;
        for (party, (answer_b, answer_rb, answer_s)) in &self.answers {
            let coefficient = coefficients
                .get(party)
                .ok_or_else(|| format!("answer from party {party} is outside the quorum"))?;
            z_b += coefficient * answer_b;
            z_rb += coefficient * answer_rb;
            z_s += coefficient * answer_s;
        }
        Ok(ProductProof {
            t_factor: combine_commitments(&self.factor_parts)?,
            t_product: combine_commitments(&self.product_parts)?,
            z_b,
            z_rb,
            z_s,
        })
    }
}

/// Assemble a product proof from recipient-scoped node contributions.
///
/// This is the distributed assembly primitive.  It never accepts a
/// `PartyId -> Scalar` share map and never reconstructs a scalar; interpolation
/// is applied only to public group elements and affine response contributions.
#[allow(clippy::too_many_arguments)]
pub fn joint_prove_product_from_contributions<R: RngCore + CryptoRng>(
    key: &Pedersen,
    c_a: &RistrettoPoint,
    product_commitment: &RistrettoPoint,
    contributions: &[ProductNodeContribution],
    quorum: &[PartyId],
    threshold: usize,
    transcript: &mut Transcript,
    rng: &mut R,
) -> Result<(ProductProof, ProductAssemblyTranscript), String> {
    if contributions.len() != quorum.len() {
        return Err(format!(
            "received {} product contributions for a quorum of {}",
            contributions.len(),
            quorum.len()
        ));
    }
    let by_party = contributions
        .iter()
        .map(|contribution| (contribution.party(), contribution))
        .collect::<BTreeMap<_, _>>();
    if by_party.len() != contributions.len()
        || by_party.keys().copied().collect::<Vec<_>>()
            != quorum
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
    {
        return Err("product contributions do not exactly match the quorum".into());
    }
    let first = contributions
        .first()
        .ok_or("a product proof needs at least one node contribution")?;
    let factor_commitment = first.factor.commitment;
    let factor_ladder = first.factor.coefficient_commitments.clone();
    if factor_ladder.len() != threshold + 1 {
        return Err("factor is missing its published VSS coefficient ladder".into());
    }
    if factor_ladder[0].compress() != factor_commitment.compress() {
        return Err("factor VSS constant does not match its commitment".into());
    }
    let mut relation_evaluations = BTreeMap::new();
    for contribution in contributions {
        let node = &contribution.factor;
        if node.commitment.compress() != factor_commitment.compress()
            || node
                .coefficient_commitments
                .iter()
                .map(|point| point.compress())
                .ne(factor_ladder.iter().map(|point| point.compress()))
        {
            return Err(format!(
                "party {} supplied a different public factor statement",
                node.party
            ));
        }
        let expected = share_commitment(&factor_ladder, node.party)?;
        let actual = key.commit(&node.value_share, &node.blinding_share);
        if actual.compress() != expected.compress() {
            return Err(format!(
                "factor share from party {} does not match the published VSS coefficient ladder",
                node.party
            ));
        }
        relation_evaluations.insert(
            node.party,
            c_a * node.value_share + key.h * contribution.cross_share,
        );
    }
    let cross_coefficient_commitments =
        coefficient_commitments_from_evaluations(&relation_evaluations, threshold)?;
    if cross_coefficient_commitments[0].compress() != product_commitment.compress() {
        return Err("product relation VSS constant does not match the product".into());
    }

    let (nonce_nodes, nonce_seals) = joint_scalar_nodes(key, quorum, threshold, 3, rng)?;
    let factor_parts = nonce_nodes
        .iter()
        .map(|node| {
            let k_b = node.share(0).ok_or("product nonce omitted k_b")?;
            let k_rb = node.share(1).ok_or("product nonce omitted k_rb")?;
            Ok((node.party(), key.commit(&k_b, &k_rb)))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let product_parts = nonce_nodes
        .iter()
        .map(|node| {
            let k_b = node.share(0).ok_or("product nonce omitted k_b")?;
            let k_s = node.share(2).ok_or("product nonce omitted k_s")?;
            Ok((node.party(), c_a * k_b + key.h * k_s))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let t_factor = combine_commitments(&factor_parts)?;
    let t_product = combine_commitments(&product_parts)?;
    let challenge = product_challenge(
        transcript,
        c_a,
        &factor_commitment,
        product_commitment,
        &t_factor,
        &t_product,
    );
    let answers = nonce_nodes
        .iter()
        .map(|nonce| {
            let contribution = by_party[&nonce.party()];
            let k_b = nonce.share(0).ok_or("product nonce omitted k_b")?;
            let k_rb = nonce.share(1).ok_or("product nonce omitted k_rb")?;
            let k_s = nonce.share(2).ok_or("product nonce omitted k_s")?;
            Ok((
                nonce.party(),
                (
                    k_b + challenge * contribution.factor.value_share,
                    k_rb + challenge * contribution.factor.blinding_share,
                    k_s + challenge * contribution.cross_share,
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let record = ProductAssemblyTranscript {
        quorum: quorum.to_vec(),
        challenge,
        c_a: *c_a,
        factor_parts,
        product_parts,
        answers,
        share_coefficient_commitments: factor_ladder,
        cross_coefficient_commitments,
        nonce_seals,
    };
    let proof = record.assemble()?;
    Ok((proof, record))
}

pub fn verify_square_bit(
    key: &Pedersen,
    commitment: &RistrettoPoint,
    proof: &ProductProof,
    transcript: &mut Transcript,
) -> bool {
    verify_product(key, transcript, commitment, commitment, commitment, proof)
}

/// Name the nodes whose product partial does not match its two published share
/// commitments.
pub fn audit_product_partials(
    key: &Pedersen,
    entry: &ProductAssemblyTranscript,
    share_coefficient_commitments: &[RistrettoPoint],
    cross_coefficient_commitments: &[RistrettoPoint],
) -> Vec<PartyId> {
    entry
        .quorum
        .iter()
        .copied()
        .filter(|party| {
            let (
                Some((z_b, z_rb, z_s)),
                Some(factor_part),
                Some(product_part),
                Ok(share_commitment),
                Ok(cross_commitment),
            ) = (
                entry.answers.get(party),
                entry.factor_parts.get(party),
                entry.product_parts.get(party),
                share_commitment(share_coefficient_commitments, *party),
                share_commitment(cross_coefficient_commitments, *party),
            )
            else {
                return true;
            };
            let factor_ok = key.commit(z_b, z_rb).compress()
                == (factor_part + share_commitment * entry.challenge).compress();
            let product_ok = (entry.c_a * z_b + key.h * z_s).compress()
                == (product_part + cross_commitment * entry.challenge).compress();
            !factor_ok || !product_ok
        })
        .collect()
}

/// Attribute using only the coefficient ladders published before the challenge.
pub fn audit_recorded_product_partials(
    key: &Pedersen,
    entry: &ProductAssemblyTranscript,
) -> Vec<PartyId> {
    audit_product_partials(
        key,
        entry,
        &entry.share_coefficient_commitments,
        &entry.cross_coefficient_commitments,
    )
}
