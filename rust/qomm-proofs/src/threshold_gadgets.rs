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
use sha2::{Digest, Sha256};

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

/// One party's opening shares for a committed wire, before public VSS
/// evaluations from the fixed committee have been assembled.
#[derive(Clone, Debug)]
pub struct LocalShared {
    party: PartyId,
    value_share: Scalar,
    blinding_share: Scalar,
    threshold: usize,
}

#[derive(Clone, Debug)]
pub struct WireEvaluation {
    pub party: PartyId,
    pub point: RistrettoPoint,
}

#[derive(Clone, Debug)]
pub struct WireStatement {
    pub commitment: RistrettoPoint,
    pub coefficient_commitments: Vec<RistrettoPoint>,
    pub threshold: usize,
}

impl LocalShared {
    pub fn new(
        party: PartyId,
        value_share: Scalar,
        blinding_share: Scalar,
        threshold: usize,
    ) -> Result<Self, String> {
        if party == 0 {
            return Err("party identifiers are one-based".into());
        }
        Ok(Self {
            party,
            value_share,
            blinding_share,
            threshold,
        })
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn evaluation(&self, key: &Pedersen) -> WireEvaluation {
        WireEvaluation {
            party: self.party,
            point: key.commit(&self.value_share, &self.blinding_share),
        }
    }

    pub fn bind(self, key: &Pedersen, statement: &WireStatement) -> Result<NodeShared, String> {
        if self.threshold != statement.threshold {
            return Err("local wire and public statement use different thresholds".into());
        }
        let expected = share_commitment(&statement.coefficient_commitments, self.party)?;
        if self.evaluation(key).point.compress() != expected.compress() {
            return Err("local wire share does not match its public VSS statement".into());
        }
        Ok(NodeShared::new(
            self.party,
            statement.commitment,
            self.value_share,
            self.blinding_share,
            statement.coefficient_commitments.clone(),
        ))
    }
}

pub fn wire_statement_from_evaluations(
    evaluations: &[WireEvaluation],
    threshold: usize,
) -> Result<WireStatement, String> {
    let points = evaluations
        .iter()
        .map(|evaluation| (evaluation.party, evaluation.point))
        .collect::<BTreeMap<_, _>>();
    if points.len() != evaluations.len() {
        return Err("a party supplied more than one wire evaluation".into());
    }
    let coefficient_commitments = coefficient_commitments_from_evaluations(&points, threshold)?;
    Ok(WireStatement {
        commitment: coefficient_commitments[0],
        coefficient_commitments,
        threshold,
    })
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

    /// Multiply a node-local committed Shamir wire by a public scalar.  This
    /// changes neither degree nor privacy and is used to remove a policy for a
    /// different public asset from a request's eligibility conjunction.
    pub(crate) fn scaled(&self, constant: &Scalar) -> Self {
        Self {
            party: self.party,
            commitment: self.commitment * constant,
            value_share: self.value_share * constant,
            blinding_share: self.blinding_share * constant,
            coefficient_commitments: self
                .coefficient_commitments
                .iter()
                .map(|point| point * constant)
                .collect(),
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

    /// Public Pedersen evaluations for the factor and product relation.  This
    /// exposes group points only and is therefore safe to send to the proof
    /// coordinator before the contribution is used in a proof round.
    pub fn evaluations(&self, key: &Pedersen, multiplicand: &RistrettoPoint) -> ProductEvaluations {
        ProductEvaluations {
            party: self.party(),
            factor: key.commit(&self.factor.value_share, &self.factor.blinding_share),
            relation: multiplicand * self.factor.value_share + key.h * self.cross_share,
        }
    }
}

/// Party-local product relation produced by the MPC.  It contains one
/// Shamir evaluation only; another party's evaluation cannot be represented by
/// this value.
#[derive(Clone, Debug)]
pub struct LocalProductShares {
    party: PartyId,
    factor_share: Scalar,
    factor_blinding_share: Scalar,
    cross_share: Scalar,
    threshold: usize,
}

impl LocalProductShares {
    pub fn new(
        party: PartyId,
        factor_share: Scalar,
        factor_blinding_share: Scalar,
        cross_share: Scalar,
        threshold: usize,
    ) -> Result<Self, String> {
        if party == 0 {
            return Err("party identifiers are one-based".into());
        }
        Ok(Self {
            party,
            factor_share,
            factor_blinding_share,
            cross_share,
            threshold,
        })
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    /// Publish commitments to this node's two scalar evaluations.  Neither
    /// scalar leaves the node.
    pub fn evaluations(&self, key: &Pedersen, multiplicand: &RistrettoPoint) -> ProductEvaluations {
        ProductEvaluations {
            party: self.party,
            factor: key.commit(&self.factor_share, &self.factor_blinding_share),
            relation: multiplicand * self.factor_share + key.h * self.cross_share,
        }
    }

    /// Bind this node's private evaluation to the public VSS ladders assembled
    /// before any proof nonce or challenge exists.
    pub fn bind(
        self,
        key: &Pedersen,
        statement: &ProductStatement,
    ) -> Result<ProductNodeContribution, String> {
        if self.threshold != statement.threshold {
            return Err("the local product handoff and statement use different thresholds".into());
        }
        let factor = key.commit(&self.factor_share, &self.factor_blinding_share);
        if factor.compress()
            != share_commitment(&statement.factor_coefficients, self.party)?.compress()
        {
            return Err("the local factor share does not match the public VSS statement".into());
        }
        let relation = statement.multiplicand * self.factor_share + key.h * self.cross_share;
        if relation.compress()
            != share_commitment(&statement.relation_coefficients, self.party)?.compress()
        {
            return Err(
                "the local product relation does not match the public VSS statement".into(),
            );
        }
        Ok(ProductNodeContribution::new(
            NodeShared::new(
                self.party,
                statement.factor_commitment,
                self.factor_share,
                self.factor_blinding_share,
                statement.factor_coefficients.clone(),
            ),
            self.cross_share,
        ))
    }
}

/// Public commitments emitted by one node before it is bound to an assembled
/// degree-`threshold` statement.
#[derive(Clone, Debug)]
pub struct ProductEvaluations {
    pub party: PartyId,
    pub factor: RistrettoPoint,
    pub relation: RistrettoPoint,
}

/// Public product statement reconstructed in the exponent.  Its constant
/// terms must be the price commitment and cash commitment respectively.
#[derive(Clone, Debug)]
pub struct ProductStatement {
    pub multiplicand: RistrettoPoint,
    pub factor_commitment: RistrettoPoint,
    pub product_commitment: RistrettoPoint,
    pub factor_coefficients: Vec<RistrettoPoint>,
    pub relation_coefficients: Vec<RistrettoPoint>,
    pub threshold: usize,
}

pub fn product_statement_from_evaluations(
    multiplicand: &RistrettoPoint,
    factor_commitment: &RistrettoPoint,
    product_commitment: &RistrettoPoint,
    evaluations: &[ProductEvaluations],
    threshold: usize,
) -> Result<ProductStatement, String> {
    if evaluations.len() < threshold + 1 {
        return Err(format!(
            "{} product evaluations cannot support threshold {threshold}",
            evaluations.len()
        ));
    }
    let unique = evaluations
        .iter()
        .map(|node| node.party)
        .collect::<BTreeSet<_>>();
    if unique.len() != evaluations.len() || unique.contains(&0) {
        return Err("a product evaluation has a duplicate or zero party".into());
    }
    let factor_coefficients = coefficient_commitments_from_evaluations(
        &evaluations
            .iter()
            .map(|node| (node.party, node.factor))
            .collect(),
        threshold,
    )?;
    let relation_coefficients = coefficient_commitments_from_evaluations(
        &evaluations
            .iter()
            .map(|node| (node.party, node.relation))
            .collect(),
        threshold,
    )?;
    if factor_coefficients[0].compress() != factor_commitment.compress() {
        return Err("product factor VSS constant does not match the committed price".into());
    }
    if relation_coefficients[0].compress() != product_commitment.compress() {
        return Err(
            "product relation VSS constant does not match the committed cash amount".into(),
        );
    }
    Ok(ProductStatement {
        multiplicand: *multiplicand,
        factor_commitment: *factor_commitment,
        product_commitment: *product_commitment,
        factor_coefficients,
        relation_coefficients,
        threshold,
    })
}

/// First public move of a product proof.  Every node first publishes only the
/// seal, then reveals these points, so a malicious node cannot choose a nonce
/// that cancels an honest node after seeing it.
#[derive(Clone, Debug)]
pub struct ProductRound1 {
    pub party: PartyId,
    pub context_digest: [u8; 32],
    pub factor: RistrettoPoint,
    pub product: RistrettoPoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductRound1Seal {
    pub party: PartyId,
    pub digest: [u8; 32],
}

pub struct ProductRound1Secret {
    party: PartyId,
    factor_nonce: Scalar,
    factor_blinding_nonce: Scalar,
    relation_nonce: Scalar,
    message_digest: [u8; 32],
    context_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ProductChallenge {
    pub quorum: Vec<PartyId>,
    pub context_digest: [u8; 32],
    pub factor: RistrettoPoint,
    pub product: RistrettoPoint,
    pub challenge: Scalar,
}

#[derive(Clone, Debug)]
pub struct ProductRound2 {
    pub party: PartyId,
    pub factor_answer: Scalar,
    pub factor_blinding_answer: Scalar,
    pub relation_answer: Scalar,
}

fn product_round1_digest(message: &ProductRound1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"QOMM:THRESHOLD-PRODUCT:ROUND1:v1");
    hasher.update((message.party as u64).to_be_bytes());
    hasher.update(message.context_digest);
    hasher.update(message.factor.compress().as_bytes());
    hasher.update(message.product.compress().as_bytes());
    hasher.finalize().into()
}

pub fn prepare_product_round1<R: RngCore + CryptoRng>(
    key: &Pedersen,
    contribution: &ProductNodeContribution,
    multiplicand: &RistrettoPoint,
    context: &[u8],
    rng: &mut R,
) -> (ProductRound1Seal, ProductRound1Secret, ProductRound1) {
    let factor_nonce = Scalar::random(&mut *rng);
    let factor_blinding_nonce = Scalar::random(&mut *rng);
    let relation_nonce = Scalar::random(&mut *rng);
    let context_digest: [u8; 32] = Sha256::digest(context).into();
    let message = ProductRound1 {
        party: contribution.party(),
        context_digest,
        factor: key.commit(&factor_nonce, &factor_blinding_nonce),
        product: multiplicand * factor_nonce + key.h * relation_nonce,
    };
    let digest = product_round1_digest(&message);
    (
        ProductRound1Seal {
            party: contribution.party(),
            digest,
        },
        ProductRound1Secret {
            party: contribution.party(),
            factor_nonce,
            factor_blinding_nonce,
            relation_nonce,
            message_digest: digest,
            context_digest,
        },
        message,
    )
}

fn checked_product_round1<'a>(
    messages: &'a [ProductRound1],
    seals: &[ProductRound1Seal],
    quorum: &[PartyId],
    context: &[u8],
) -> Result<BTreeMap<PartyId, &'a ProductRound1>, String> {
    let expected_context: [u8; 32] = Sha256::digest(context).into();
    let by_party = messages
        .iter()
        .map(|message| (message.party, message))
        .collect::<BTreeMap<_, _>>();
    let seal_by_party = seals
        .iter()
        .map(|seal| (seal.party, seal))
        .collect::<BTreeMap<_, _>>();
    if by_party.len() != quorum.len()
        || seal_by_party.len() != quorum.len()
        || quorum.iter().copied().collect::<BTreeSet<_>>().len() != quorum.len()
        || quorum
            .iter()
            .any(|party| !by_party.contains_key(party) || !seal_by_party.contains_key(party))
    {
        return Err("product round-one messages and seals do not exactly match the quorum".into());
    }
    for party in quorum {
        let message = by_party[party];
        if message.context_digest != expected_context
            || product_round1_digest(message) != seal_by_party[party].digest
        {
            return Err(format!(
                "party {party} supplied an invalid product round-one reveal"
            ));
        }
    }
    Ok(by_party)
}

pub fn make_product_challenge(
    statement: &ProductStatement,
    messages: &[ProductRound1],
    seals: &[ProductRound1Seal],
    quorum: &[PartyId],
    context: &'static [u8],
) -> Result<ProductChallenge, String> {
    make_product_challenge_with_transcript(
        statement,
        messages,
        seals,
        quorum,
        context,
        &mut Transcript::new(context),
    )
}

/// Quote proofs use a structured Merlin transcript whose statement digest and
/// maker index cannot be represented by a single static transcript label.
/// This variant keeps the round-one seal bound to explicit context bytes while
/// deriving the Fiat-Shamir challenge from the caller's exact transcript.
pub fn make_product_challenge_with_transcript(
    statement: &ProductStatement,
    messages: &[ProductRound1],
    seals: &[ProductRound1Seal],
    quorum: &[PartyId],
    context: &[u8],
    transcript: &mut Transcript,
) -> Result<ProductChallenge, String> {
    let by_party = checked_product_round1(messages, seals, quorum, context)?;
    let factor = combine_commitments(
        &quorum
            .iter()
            .map(|party| (*party, by_party[party].factor))
            .collect(),
    )?;
    let product = combine_commitments(
        &quorum
            .iter()
            .map(|party| (*party, by_party[party].product))
            .collect(),
    )?;
    let challenge = product_challenge(
        transcript,
        &statement.multiplicand,
        &statement.factor_commitment,
        &statement.product_commitment,
        &factor,
        &product,
    );
    Ok(ProductChallenge {
        quorum: quorum.to_vec(),
        context_digest: Sha256::digest(context).into(),
        factor,
        product,
        challenge,
    })
}

pub fn answer_product_challenge(
    contribution: &ProductNodeContribution,
    secret: ProductRound1Secret,
    challenge: &ProductChallenge,
) -> Result<ProductRound2, String> {
    if contribution.party() != secret.party
        || !challenge.quorum.contains(&secret.party)
        || secret.message_digest == [0u8; 32]
        || secret.context_digest != challenge.context_digest
    {
        return Err("product challenge does not match this node's sealed first round".into());
    }
    Ok(ProductRound2 {
        party: secret.party,
        factor_answer: secret.factor_nonce + challenge.challenge * contribution.factor.value_share,
        factor_blinding_answer: secret.factor_blinding_nonce
            + challenge.challenge * contribution.factor.blinding_share,
        relation_answer: secret.relation_nonce + challenge.challenge * contribution.cross_share,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_product_from_rounds(
    key: &Pedersen,
    statement: &ProductStatement,
    messages: &[ProductRound1],
    seals: &[ProductRound1Seal],
    responses: &[ProductRound2],
    quorum: &[PartyId],
    context: &'static [u8],
) -> Result<ProductProof, String> {
    assemble_product_from_rounds_with_transcript(
        key,
        statement,
        messages,
        seals,
        responses,
        quorum,
        context,
        &mut Transcript::new(context),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_product_from_rounds_with_transcript(
    key: &Pedersen,
    statement: &ProductStatement,
    messages: &[ProductRound1],
    seals: &[ProductRound1Seal],
    responses: &[ProductRound2],
    quorum: &[PartyId],
    context: &[u8],
    transcript: &mut Transcript,
) -> Result<ProductProof, String> {
    let mut verify_transcript = transcript.clone();
    let challenge = make_product_challenge_with_transcript(
        statement, messages, seals, quorum, context, transcript,
    )?;
    let first = messages
        .iter()
        .map(|message| (message.party, message))
        .collect::<BTreeMap<_, _>>();
    let answers = responses
        .iter()
        .map(|answer| (answer.party, answer))
        .collect::<BTreeMap<_, _>>();
    if answers.len() != quorum.len() || quorum.iter().any(|party| !answers.contains_key(party)) {
        return Err("product responses do not exactly match the quorum".into());
    }
    for party in quorum {
        let answer = answers[party];
        let factor_evaluation = share_commitment(&statement.factor_coefficients, *party)?;
        if key
            .commit(&answer.factor_answer, &answer.factor_blinding_answer)
            .compress()
            != (first[party].factor + factor_evaluation * challenge.challenge).compress()
        {
            return Err(format!(
                "party {party} supplied a bad product factor answer"
            ));
        }
        let relation_evaluation = share_commitment(&statement.relation_coefficients, *party)?;
        if (statement.multiplicand * answer.factor_answer + key.h * answer.relation_answer)
            .compress()
            != (first[party].product + relation_evaluation * challenge.challenge).compress()
        {
            return Err(format!(
                "party {party} supplied a bad product relation answer"
            ));
        }
    }
    let coefficients = lagrange_at_zero(quorum)?;
    let mut proof = ProductProof {
        t_factor: challenge.factor,
        t_product: challenge.product,
        z_b: Scalar::ZERO,
        z_rb: Scalar::ZERO,
        z_s: Scalar::ZERO,
    };
    for party in quorum {
        let coefficient = coefficients[party];
        let answer = answers[party];
        proof.z_b += coefficient * answer.factor_answer;
        proof.z_rb += coefficient * answer.factor_blinding_answer;
        proof.z_s += coefficient * answer.relation_answer;
    }
    if !verify_product(
        key,
        &mut verify_transcript,
        &statement.multiplicand,
        &statement.factor_commitment,
        &statement.product_commitment,
        &proof,
    ) {
        return Err("assembled threshold product proof does not verify".into());
    }
    Ok(proof)
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
