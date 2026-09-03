//! Whole quote proofs assembled by a quorum that holds only Shamir shares.
//!
//! `deal_quote_shares` models the output shape of the MPC: every multiplication
//! output has been degree-reduced, every bit decomposition has been shared, and
//! the public winner is available. `joint_prove_quote` accepts that handoff and
//! the public statement, never a [`MakerWitness`]. It emits the same
//! [`QuoteProof`] accepted by [`QuoteCircuit::verify`].

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};

use crate::quote_proof::{
    registry_digest, scalar, BitValidityProof, EligibilityProof, Gate, MakerCommitments,
    MakerProof, MakerWitness, MinimalityProof, Public, QuoteCircuit, QuoteProof, Registered,
    RegisteredPolicy,
};
use crate::threshold_gadgets::{
    add, answer_product_challenge, assemble_product_from_rounds_with_transcript,
    joint_prove_product_from_contributions, make_product_challenge_with_transcript, negate,
    prepare_product_round1, product_statement_from_evaluations, scale, shift, sub,
    wire_statement_from_evaluations, LocalShared, NodeShared, ProductAssemblyTranscript,
    ProductChallenge, ProductEvaluations, ProductNodeContribution, ProductRound1,
    ProductRound1Seal, ProductRound1Secret, ProductRound2, ProductStatement, Shared,
    WireEvaluation, WireStatement,
};
use crate::threshold_range::{
    answer_range_challenge, assemble_range_from_rounds, bits_for,
    joint_prove_range_from_contributions, make_range_challenge, prepare_range_round1,
    range_relations_from_evaluations, range_statement_from_evaluations, LocalRangeShares,
    NodeValueShares, RangeAssemblyTranscript, RangeChallenge, RangeEvaluations,
    RangeRelationEvaluations, RangeRelationStatement, RangeRound1, RangeRound1Seal,
    RangeRound1Secret, RangeRound2, RangeStatement, ThresholdRangeProof, ValueShares,
};
use crate::threshold_sigma::{
    answer_opening_challenge, assemble_opening_from_rounds_with_transcript, deal,
    joint_opening_from_contributions, make_opening_challenge_with_transcript,
    prepare_opening_round1, share_scalar, OpeningAssemblyTranscript, OpeningChallenge,
    OpeningNodeContribution, OpeningRound1, OpeningRound1Seal, OpeningRound1Secret, OpeningRound2,
    PartyId, ScalarShares,
};

fn checked_add(a: i64, b: i64, message: &'static str) -> Result<i64, String> {
    a.checked_add(b).ok_or_else(|| message.to_string())
}

fn checked_sub(a: i64, b: i64, message: &'static str) -> Result<i64, String> {
    a.checked_sub(b).ok_or_else(|| message.to_string())
}

fn checked_mul(a: i64, b: i64, message: &'static str) -> Result<i64, String> {
    a.checked_mul(b).ok_or_else(|| message.to_string())
}

fn scalar_to_u64(value: i64, message: &'static str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| message.to_string())
}

struct Dealer<'a, R> {
    key: &'a Pedersen,
    parties: &'a [PartyId],
    threshold: usize,
    rng: &'a mut R,
}

impl<R: RngCore + CryptoRng> Dealer<'_, R> {
    fn random_scalar(&mut self) -> Scalar {
        Scalar::random(&mut *self.rng)
    }

    fn wire(&mut self, value: i64, blinding: Scalar) -> Result<Shared, String> {
        let value = scalar(value);
        let shared = deal(
            self.key,
            &value,
            &blinding,
            self.parties,
            self.threshold,
            &mut *self.rng,
        )?;
        Ok(Shared {
            commitment: shared.commitment,
            value: shared.value_shares,
            blinding: shared.blinding_shares,
            coefficient_commitments: shared.coefficient_commitments,
        })
    }

    fn cross(
        &mut self,
        output_blinding: &Scalar,
        first_blinding: &Scalar,
        second_value: &Scalar,
    ) -> Result<ScalarShares, String> {
        share_scalar(
            &(output_blinding - first_blinding * second_value),
            self.parties,
            self.threshold,
            &mut *self.rng,
        )
    }

    fn square_cross(&mut self, blinding: &Scalar, bit: bool) -> Result<ScalarShares, String> {
        self.square_cross_scalar(blinding, &Scalar::from(u64::from(bit)))
    }

    fn square_cross_scalar(
        &mut self,
        blinding: &Scalar,
        bit: &Scalar,
    ) -> Result<ScalarShares, String> {
        share_scalar(
            &(blinding * (Scalar::ONE - bit)),
            self.parties,
            self.threshold,
            &mut *self.rng,
        )
    }

    #[cfg(any())]
    fn blinded(
        &mut self,
        value: &ScalarShares,
        quorum: &[PartyId],
    ) -> Result<(Shared, ScalarShares), String> {
        let blinding = self.random_scalar();
        let blinding_shares =
            share_scalar(&blinding, self.parties, self.threshold, &mut *self.rng)?;
        let commitment = commitment_from_shares(self.key, value, &blinding_shares, quorum)?;
        let public_evaluations = value
            .iter()
            .map(|(party, value)| (*party, self.key.commit(value, &blinding_shares[party])))
            .collect();
        let coefficient_commitments =
            coefficient_commitments_from_evaluations(&public_evaluations, self.threshold)?;
        Ok((
            Shared {
                commitment,
                value: value.clone(),
                blinding: blinding_shares.clone(),
                coefficient_commitments,
            },
            blinding_shares,
        ))
    }
}

#[derive(Clone, Debug)]
struct DealerPolicyShares {
    pub ask_level: Shared,
    pub spread: Shared,
    pub slope: Shared,
    pub invcoef: Shared,
    pub inv: Shared,
    pub maxqty: Shared,
    pub expiry: Shared,
    pub active: Shared,
    pub use_ref: Shared,
}

impl DealerPolicyShares {
    #[cfg(any())]
    fn wires(&self) -> [&Shared; 9] {
        [
            &self.ask_level,
            &self.spread,
            &self.slope,
            &self.invcoef,
            &self.inv,
            &self.maxqty,
            &self.expiry,
            &self.active,
            &self.use_ref,
        ]
    }
}

#[derive(Clone, Debug)]
struct DealerGateShares {
    pub value: Shared,
    pub holds: Shared,
    pub holds_cross: ScalarShares,
    pub product: Shared,
    pub product_cross: ScalarShares,
    pub witness: Shared,
    pub bits: ValueShares,
    holds_blinding: Scalar,
}

#[derive(Clone, Debug)]
struct DealerMakerShares {
    pub fields: DealerPolicyShares,
    pub depth: Shared,
    pub depth_cross: ScalarShares,
    pub skew: Shared,
    pub skew_cross: ScalarShares,
    pub fits: DealerGateShares,
    pub fresh: DealerGateShares,
    pub active_cross: ScalarShares,
    pub reference_cross: ScalarShares,
    pub both: Shared,
    pub both_cross: ScalarShares,
    pub ok: Shared,
    pub ok_cross: ScalarShares,
    pub gated: Shared,
    pub gated_cross: ScalarShares,
    pub cost: Shared,
    pub shifted_cost: Shared,
    pub packed: Shared,
}

impl DealerMakerShares {
    #[cfg(any())]
    fn shared_wires(&self) -> Vec<&Shared> {
        let mut wires = self.fields.wires().to_vec();
        wires.extend([
            &self.depth,
            &self.skew,
            &self.both,
            &self.ok,
            &self.gated,
            &self.cost,
            &self.shifted_cost,
            &self.packed,
            &self.fits.value,
            &self.fits.holds,
            &self.fits.product,
            &self.fits.witness,
            &self.fresh.value,
            &self.fresh.holds,
            &self.fresh.product,
            &self.fresh.witness,
        ]);
        wires
    }
}

#[derive(Clone, Debug)]
struct DealerQuoteShares {
    pub qty: Shared,
    pub makers: Vec<DealerMakerShares>,
    pub winner_index: usize,
    pub winner_value: u64,
    pub minimality: Vec<ValueShares>,
    pub key_wires: Vec<Shared>,
    pub threshold: usize,
    pub parties: Vec<PartyId>,
}

impl DealerQuoteShares {
    fn node_contributions(&self) -> Result<Vec<QuoteNodeContribution>, String> {
        self.parties
            .iter()
            .map(|party| self.node_contribution(*party))
            .collect()
    }

    fn node_contribution(&self, party: PartyId) -> Result<QuoteNodeContribution, String> {
        Ok(QuoteNodeContribution {
            party,
            qty: self
                .qty
                .node_share(party)
                .ok_or_else(|| format!("quantity omitted party {party}"))?,
            makers: self
                .makers
                .iter()
                .map(|maker| node_maker(maker, party))
                .collect::<Result<Vec<_>, _>>()?,
            winner_index: self.winner_index,
            winner_value: self.winner_value,
            minimality: self
                .minimality
                .iter()
                .map(|range| {
                    range
                        .node_contribution(party)
                        .ok_or_else(|| format!("minimality range omitted party {party}"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            key_wires: self
                .key_wires
                .iter()
                .map(|wire| {
                    wire.node_share(party)
                        .ok_or_else(|| format!("key wire omitted party {party}"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            threshold: self.threshold,
            parties: self.parties.clone(),
        })
    }
}

#[derive(Clone, Debug)]
struct NodePolicyShares {
    ask_level: NodeShared,
    spread: NodeShared,
    slope: NodeShared,
    invcoef: NodeShared,
    inv: NodeShared,
    maxqty: NodeShared,
    expiry: NodeShared,
    active: NodeShared,
    use_ref: NodeShared,
}

impl NodePolicyShares {
    fn wires(&self) -> [&NodeShared; 9] {
        [
            &self.ask_level,
            &self.spread,
            &self.slope,
            &self.invcoef,
            &self.inv,
            &self.maxqty,
            &self.expiry,
            &self.active,
            &self.use_ref,
        ]
    }
}

#[derive(Clone, Debug)]
struct NodeGateShares {
    value: NodeShared,
    holds: NodeShared,
    holds_cross: Scalar,
    product: NodeShared,
    product_cross: Scalar,
    witness: NodeShared,
    bits: NodeValueShares,
}

#[derive(Clone, Debug)]
struct NodeMakerShares {
    fields: NodePolicyShares,
    depth: NodeShared,
    depth_cross: Scalar,
    skew: NodeShared,
    skew_cross: Scalar,
    fits: NodeGateShares,
    fresh: NodeGateShares,
    active_cross: Scalar,
    reference_cross: Scalar,
    both: NodeShared,
    both_cross: Scalar,
    ok: NodeShared,
    ok_cross: Scalar,
    gated: NodeShared,
    gated_cross: Scalar,
    cost: NodeShared,
    shifted_cost: NodeShared,
    packed: NodeShared,
}

impl NodeMakerShares {
    fn shared_wires(&self) -> Vec<&NodeShared> {
        let mut wires = self.fields.wires().to_vec();
        wires.extend([
            &self.depth,
            &self.skew,
            &self.both,
            &self.ok,
            &self.gated,
            &self.cost,
            &self.shifted_cost,
            &self.packed,
            &self.fits.value,
            &self.fits.holds,
            &self.fits.product,
            &self.fits.witness,
            &self.fresh.value,
            &self.fresh.holds,
            &self.fresh.product,
            &self.fresh.witness,
        ]);
        wires
    }
}

/// Exactly one party's private quote material plus the public commitments.
/// No field is a map keyed by another party.
#[derive(Clone, Debug)]
pub struct QuoteNodeContribution {
    party: PartyId,
    qty: NodeShared,
    makers: Vec<NodeMakerShares>,
    winner_index: usize,
    winner_value: u64,
    minimality: Vec<NodeValueShares>,
    key_wires: Vec<NodeShared>,
    threshold: usize,
    parties: Vec<PartyId>,
}

impl QuoteNodeContribution {
    pub fn party(&self) -> PartyId {
        self.party
    }

    pub fn node_view(&self) -> NodeQuoteView {
        let wires = self.shared_wires();
        let (wire_shares, wire_blinding_shares): (Vec<_>, Vec<_>) =
            wires.iter().map(|wire| wire.own_evaluation()).unzip();
        let mut range_bit_shares = Vec::new();
        let mut range_bit_blinding_shares = Vec::new();
        let mut cross_shares = self
            .makers
            .iter()
            .flat_map(|maker| {
                [
                    maker.depth_cross,
                    maker.skew_cross,
                    maker.fits.holds_cross,
                    maker.fits.product_cross,
                    maker.fresh.holds_cross,
                    maker.fresh.product_cross,
                    maker.active_cross,
                    maker.reference_cross,
                    maker.both_cross,
                    maker.ok_cross,
                    maker.gated_cross,
                ]
            })
            .collect::<Vec<_>>();
        for range in self
            .makers
            .iter()
            .flat_map(|maker| [&maker.fits.bits, &maker.fresh.bits])
            .chain(self.minimality.iter())
        {
            for (value, blinding, cross) in range.bit_evaluations() {
                range_bit_shares.push(value);
                range_bit_blinding_shares.push(blinding);
                cross_shares.push(cross);
            }
        }
        NodeQuoteView {
            party: self.party,
            wire_shares,
            wire_blinding_shares,
            range_bit_shares,
            range_bit_blinding_shares,
            cross_shares,
        }
    }

    fn shared_wires(&self) -> Vec<&NodeShared> {
        let mut wires = vec![&self.qty];
        for maker in &self.makers {
            wires.extend(maker.shared_wires());
        }
        wires.extend(self.key_wires.iter());
        wires
    }
}

/// Compatibility name for callers written before quote handoffs were made
/// explicitly recipient-scoped.  One value is still exactly one node's
/// contribution; it is not an aggregate share container.
pub type QuoteShares = QuoteNodeContribution;

/// Everything one hostile node legitimately receives.  Each vector contains
/// only evaluations at `party`; public commitments are obtained from `Public`.
#[derive(Clone, Debug)]
pub struct NodeQuoteView {
    pub party: PartyId,
    pub wire_shares: Vec<Scalar>,
    pub wire_blinding_shares: Vec<Scalar>,
    pub range_bit_shares: Vec<Scalar>,
    pub range_bit_blinding_shares: Vec<Scalar>,
    pub cross_shares: Vec<Scalar>,
}

/// Party-local quote material read from one MPC persistence file.  Every
/// committed wire is represented by exactly one Shamir evaluation and its
/// Pedersen-blinding evaluation; no map of other parties' shares can be stored
/// in this type.
#[derive(Clone, Debug)]
pub struct LocalQuotePolicyInput {
    pub ask_level: LocalShared,
    pub spread: LocalShared,
    pub slope: LocalShared,
    pub invcoef: LocalShared,
    pub inv: LocalShared,
    pub maxqty: LocalShared,
    pub expiry: LocalShared,
    pub active: LocalShared,
    pub use_ref: LocalShared,
}

impl LocalQuotePolicyInput {
    fn wires(&self) -> [&LocalShared; 9] {
        [
            &self.ask_level,
            &self.spread,
            &self.slope,
            &self.invcoef,
            &self.inv,
            &self.maxqty,
            &self.expiry,
            &self.active,
            &self.use_ref,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct LocalQuoteGateInput {
    pub value: LocalShared,
    pub holds: LocalShared,
    pub holds_cross: Scalar,
    pub product: LocalShared,
    pub product_cross: Scalar,
    /// Bit decomposition of `2 * product - value + holds - 1`.
    pub witness: LocalRangeShares,
}

#[derive(Clone, Debug)]
pub struct LocalQuoteMakerInput {
    pub fields: LocalQuotePolicyInput,
    pub depth: LocalShared,
    pub depth_cross: Scalar,
    pub skew: LocalShared,
    pub skew_cross: Scalar,
    pub fits: LocalQuoteGateInput,
    pub fresh: LocalQuoteGateInput,
    pub active_cross: Scalar,
    pub reference_cross: Scalar,
    pub both: LocalShared,
    pub both_cross: Scalar,
    pub ok: LocalShared,
    pub ok_cross: Scalar,
    pub gated: LocalShared,
    pub gated_cross: Scalar,
    pub cost: LocalShared,
    pub packed: LocalShared,
    pub minimality: LocalRangeShares,
}

impl LocalQuoteMakerInput {
    fn wires(&self) -> Vec<&LocalShared> {
        let mut wires = self.fields.wires().to_vec();
        wires.extend([
            &self.depth,
            &self.skew,
            &self.fits.value,
            &self.fits.holds,
            &self.fits.product,
            &self.fresh.value,
            &self.fresh.holds,
            &self.fresh.product,
            &self.both,
            &self.ok,
            &self.gated,
            &self.cost,
            &self.packed,
        ]);
        wires
    }

    fn ranges(&self) -> [&LocalRangeShares; 3] {
        [&self.fits.witness, &self.fresh.witness, &self.minimality]
    }
}

const LOCAL_WIRES_PER_MAKER: usize = 22;
const LOCAL_RANGES_PER_MAKER: usize = 3;

#[derive(Clone, Debug)]
pub struct LocalQuoteNode {
    party: PartyId,
    qty: LocalShared,
    makers: Vec<LocalQuoteMakerInput>,
    threshold: usize,
    parties: Vec<PartyId>,
}

impl LocalQuoteNode {
    pub fn new(
        qty: LocalShared,
        makers: Vec<LocalQuoteMakerInput>,
        parties: Vec<PartyId>,
        threshold: usize,
    ) -> Result<Self, String> {
        if makers.is_empty() {
            return Err("a local quote handoff needs at least one maker".into());
        }
        let party = qty.party();
        if parties.len() <= threshold
            || !parties.contains(&party)
            || parties
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != parties.len()
            || parties.contains(&0)
        {
            return Err("the local quote committee is malformed".into());
        }
        if makers.iter().any(|maker| {
            maker.wires().iter().any(|wire| wire.party() != party)
                || maker.ranges().iter().any(|range| range.party() != party)
        }) {
            return Err("a local quote handoff mixes material from different parties".into());
        }
        Ok(Self {
            party,
            qty,
            makers,
            threshold,
            parties,
        })
    }

    pub fn party(&self) -> PartyId {
        self.party
    }

    fn wires(&self) -> Vec<&LocalShared> {
        let mut wires = vec![&self.qty];
        for maker in &self.makers {
            wires.extend(maker.wires());
        }
        wires
    }

    fn ranges(&self) -> Vec<&LocalRangeShares> {
        self.makers
            .iter()
            .flat_map(LocalQuoteMakerInput::ranges)
            .collect()
    }

    pub fn evaluations(&self, key: &Pedersen) -> QuoteNodeEvaluations {
        QuoteNodeEvaluations {
            party: self.party,
            wires: self
                .wires()
                .into_iter()
                .map(|wire| wire.evaluation(key))
                .collect(),
            ranges: self
                .ranges()
                .into_iter()
                .map(|range| range.evaluations(key))
                .collect(),
        }
    }

    /// Bind this node's private evaluations to a statement reconstructed only
    /// from public group points.  The returned contribution remains in this
    /// process and is suitable for the public multi-round proof APIs.
    pub fn bind(
        self,
        key: &Pedersen,
        statement: &QuoteNodeStatement,
    ) -> Result<QuoteNodeContribution, String> {
        if self.threshold != statement.threshold
            || self.parties != statement.parties
            || self.makers.len() != statement.maker_count
        {
            return Err(
                "the local quote handoff and public statement have different shapes".into(),
            );
        }
        let local_wires = self.wires();
        if local_wires.len() != statement.wires.len() {
            return Err("the local quote handoff has the wrong wire count".into());
        }
        // Consume the local inputs only after the shape check above.
        let LocalQuoteNode {
            party,
            qty,
            makers,
            threshold,
            parties,
        } = self;
        let mut wire_statements = statement.wires.iter();
        let qty = qty.bind(
            key,
            wire_statements
                .next()
                .ok_or("the quote statement omitted quantity")?,
        )?;
        let mut ranges = statement.ranges.iter();
        let mut bound_makers = Vec::with_capacity(makers.len());
        let mut minimality = Vec::with_capacity(makers.len());
        let mut key_wires = Vec::with_capacity(makers.len());
        for maker in makers {
            let mut bind_wire = |wire: LocalShared| -> Result<NodeShared, String> {
                wire.bind(
                    key,
                    wire_statements
                        .next()
                        .ok_or("the quote statement omitted a maker wire")?,
                )
            };
            let fields = NodePolicyShares {
                ask_level: bind_wire(maker.fields.ask_level)?,
                spread: bind_wire(maker.fields.spread)?,
                slope: bind_wire(maker.fields.slope)?,
                invcoef: bind_wire(maker.fields.invcoef)?,
                inv: bind_wire(maker.fields.inv)?,
                maxqty: bind_wire(maker.fields.maxqty)?,
                expiry: bind_wire(maker.fields.expiry)?,
                active: bind_wire(maker.fields.active)?,
                use_ref: bind_wire(maker.fields.use_ref)?,
            };
            let depth = bind_wire(maker.depth)?;
            let skew = bind_wire(maker.skew)?;
            let fits_value = bind_wire(maker.fits.value)?;
            let fits_holds = bind_wire(maker.fits.holds)?;
            let fits_product = bind_wire(maker.fits.product)?;
            let fresh_value = bind_wire(maker.fresh.value)?;
            let fresh_holds = bind_wire(maker.fresh.holds)?;
            let fresh_product = bind_wire(maker.fresh.product)?;
            let both = bind_wire(maker.both)?;
            let ok = bind_wire(maker.ok)?;
            let gated = bind_wire(maker.gated)?;
            let cost = bind_wire(maker.cost)?;
            let packed = bind_wire(maker.packed)?;
            let fits_bits = maker.fits.witness.bind(
                key,
                ranges
                    .next()
                    .ok_or("the quote statement omitted the fits range")?,
            )?;
            let fresh_bits = maker.fresh.witness.bind(
                key,
                ranges
                    .next()
                    .ok_or("the quote statement omitted the freshness range")?,
            )?;
            let minimum = maker.minimality.bind(
                key,
                ranges
                    .next()
                    .ok_or("the quote statement omitted a minimality range")?,
            )?;
            let shifted_cost = cost.shifted(key, &-scalar(statement.sentinel));
            let fits = NodeGateShares {
                value: fits_value,
                holds: fits_holds,
                holds_cross: maker.fits.holds_cross,
                product: fits_product,
                product_cross: maker.fits.product_cross,
                witness: fits_bits.as_node_shared(),
                bits: fits_bits,
            };
            let fresh = NodeGateShares {
                value: fresh_value,
                holds: fresh_holds,
                holds_cross: maker.fresh.holds_cross,
                product: fresh_product,
                product_cross: maker.fresh.product_cross,
                witness: fresh_bits.as_node_shared(),
                bits: fresh_bits,
            };
            key_wires.push(packed.clone());
            minimality.push(minimum);
            bound_makers.push(NodeMakerShares {
                fields,
                depth,
                depth_cross: maker.depth_cross,
                skew,
                skew_cross: maker.skew_cross,
                fits,
                fresh,
                active_cross: maker.active_cross,
                reference_cross: maker.reference_cross,
                both,
                both_cross: maker.both_cross,
                ok,
                ok_cross: maker.ok_cross,
                gated,
                gated_cross: maker.gated_cross,
                cost,
                shifted_cost,
                packed,
            });
        }
        if wire_statements.next().is_some() || ranges.next().is_some() {
            return Err("the quote statement contains unused wires".into());
        }
        Ok(QuoteNodeContribution {
            party,
            qty,
            makers: bound_makers,
            winner_index: statement.winner_index,
            winner_value: statement.winner_value,
            minimality,
            key_wires,
            threshold,
            parties,
        })
    }
}

/// Public, share-hiding group evaluations from one proof node.
#[derive(Clone, Debug)]
pub struct QuoteNodeEvaluations {
    pub party: PartyId,
    pub wires: Vec<WireEvaluation>,
    pub ranges: Vec<RangeEvaluations>,
}

/// Public VSS statement fixed before any proof nonce or challenge exists.
#[derive(Clone, Debug)]
pub struct QuoteNodeStatement {
    pub wires: Vec<WireStatement>,
    pub ranges: Vec<RangeStatement>,
    pub winner_index: usize,
    pub winner_value: u64,
    pub maker_count: usize,
    pub sentinel: i64,
    pub threshold: usize,
    pub parties: Vec<PartyId>,
}

fn same_point(left: &RistrettoPoint, right: &RistrettoPoint) -> bool {
    left.compress() == right.compress()
}

/// Reconstruct the complete quote statement in the exponent and reject any
/// set of node evaluations that is not the registered policy computation.
/// No scalar share is accepted by this function.
#[allow(clippy::too_many_arguments)]
pub fn quote_statement_from_evaluations(
    circuit: &QuoteCircuit,
    evaluations: &[QuoteNodeEvaluations],
    public: &Public,
    winner_index: usize,
    winner_value: u64,
    parties: &[PartyId],
    threshold: usize,
) -> Result<QuoteNodeStatement, String> {
    let maker_count = public.registry.len();
    if maker_count == 0
        || winner_index >= maker_count
        || public.direction > 1
        || public.n_slots <= 0
        || usize::try_from(public.n_slots)
            .ok()
            .is_none_or(|slots| slots < maker_count)
        || public.registry_digest != registry_digest(&public.registry)
    {
        return Err("the public quote statement is malformed".into());
    }
    if parties.len() <= threshold
        || evaluations.len() < threshold + 1
        || parties
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != parties.len()
        || parties.contains(&0)
    {
        return Err("the quote committee cannot support its threshold".into());
    }
    let expected_wires = 1 + maker_count * LOCAL_WIRES_PER_MAKER;
    let expected_ranges = maker_count * LOCAL_RANGES_PER_MAKER;
    let mut seen = std::collections::BTreeSet::new();
    for node in evaluations {
        if !seen.insert(node.party)
            || !parties.contains(&node.party)
            || node.wires.len() != expected_wires
            || node.ranges.len() != expected_ranges
            || node.wires.iter().any(|wire| wire.party != node.party)
            || node.ranges.iter().any(|range| range.party != node.party)
        {
            return Err("quote node evaluations have different shapes or parties".into());
        }
    }
    let mut wires = Vec::with_capacity(expected_wires);
    for index in 0..expected_wires {
        wires.push(wire_statement_from_evaluations(
            &evaluations
                .iter()
                .map(|node| node.wires[index].clone())
                .collect::<Vec<_>>(),
            threshold,
        )?);
    }
    let mut ranges = Vec::with_capacity(expected_ranges);
    for index in 0..expected_ranges {
        ranges.push(range_statement_from_evaluations(
            &evaluations
                .iter()
                .map(|node| node.ranges[index].clone())
                .collect::<Vec<_>>(),
            threshold,
        )?);
    }
    if !same_point(&wires[0].commitment, &public.qty_commitment) {
        return Err("MPC quantity commitment differs from the request".into());
    }
    let key = &circuit.key;
    let maker_wire = |maker: usize, offset: usize| -> &WireStatement {
        &wires[1 + maker * LOCAL_WIRES_PER_MAKER + offset]
    };
    let maker_range = |maker: usize, offset: usize| -> &RangeStatement {
        &ranges[maker * LOCAL_RANGES_PER_MAKER + offset]
    };
    let strict_now = public
        .now
        .checked_add(1)
        .ok_or("strict expiry timestamp overflow")?;
    for (index, registered) in public.registry.iter().enumerate() {
        let registered_points = [
            registered.ask_level,
            registered.spread,
            registered.slope,
            registered.invcoef,
            registered.inv,
            registered.maxqty,
            registered.expiry,
            registered.active,
            registered.use_ref,
        ];
        for (offset, point) in registered_points.iter().enumerate() {
            if !same_point(&maker_wire(index, offset).commitment, point) {
                return Err(format!(
                    "maker {index} MPC policy wire {offset} differs from the registry"
                ));
            }
        }
        let depth = &maker_wire(index, 9).commitment;
        let skew = &maker_wire(index, 10).commitment;
        let fits_value = &maker_wire(index, 11).commitment;
        let fits_holds = &maker_wire(index, 12).commitment;
        let fits_product = &maker_wire(index, 13).commitment;
        let fresh_value = &maker_wire(index, 14).commitment;
        let fresh_holds = &maker_wire(index, 15).commitment;
        let fresh_product = &maker_wire(index, 16).commitment;
        let both = &maker_wire(index, 17).commitment;
        let ok = &maker_wire(index, 18).commitment;
        let gated = &maker_wire(index, 19).commitment;
        let cost = &maker_wire(index, 20).commitment;
        let packed = &maker_wire(index, 21).commitment;
        if !same_point(fits_value, &(registered.maxqty - public.qty_commitment)) {
            return Err(format!("maker {index} size margin is not maxqty - qty"));
        }
        if !same_point(
            fresh_value,
            &(registered.expiry - key.g * scalar(strict_now)),
        ) {
            return Err(format!("maker {index} freshness margin is incorrect"));
        }
        let fits_witness = fits_product + fits_product - fits_value + fits_holds - key.g;
        let fresh_witness = fresh_product + fresh_product - fresh_value + fresh_holds - key.g;
        if !same_point(&maker_range(index, 0).commitment, &fits_witness)
            || !same_point(&maker_range(index, 1).commitment, &fresh_witness)
            || maker_range(index, 0).bit_commitments.len() != circuit.eligibility_bits() + 2
            || maker_range(index, 1).bit_commitments.len() != circuit.eligibility_bits() + 2
            || maker_range(index, 2).bit_commitments.len() != circuit.span_bits()
        {
            return Err(format!(
                "maker {index} range statement is not the quote witness"
            ));
        }
        let anchor = registered.ask_level + registered.use_ref * scalar(public.reference_price);
        let ask = anchor + depth + skew;
        let bid = anchor - registered.spread - depth + skew;
        let expected_cost = if public.direction == 1 { -bid } else { ask };
        if !same_point(cost, &expected_cost) {
            return Err(format!(
                "maker {index} cost is not the registered price formula"
            ));
        }
        let constant = public
            .sentinel
            .checked_mul(2)
            .and_then(|value| value.checked_mul(public.n_slots))
            .and_then(|value| value.checked_add(index as i64))
            .ok_or("packed quote-key constant overflow")?;
        let expected_packed = gated * scalar(public.n_slots) + key.g * scalar(constant);
        if !same_point(packed, &expected_packed) {
            return Err(format!("maker {index} packed key is incorrect"));
        }
        // These commitments are referenced by later product proofs. Touching
        // them here makes the intended fixed layout explicit.
        let _ = (both, ok);
    }
    let winner_key = maker_wire(winner_index, 21).commitment;
    for index in 0..maker_count {
        let expected = maker_wire(index, 21).commitment - winner_key;
        if !same_point(&maker_range(index, 2).commitment, &expected) {
            return Err(format!(
                "maker {index} minimality value is not key - winner"
            ));
        }
    }
    Ok(QuoteNodeStatement {
        wires,
        ranges,
        winner_index,
        winner_value,
        maker_count,
        sentinel: public.sentinel,
        threshold,
        parties: parties.to_vec(),
    })
}

#[derive(Clone, Debug)]
pub struct QuoteRelationEvaluations {
    pub party: PartyId,
    pub products: Vec<ProductEvaluations>,
    pub ranges: Vec<RangeRelationEvaluations>,
}

#[derive(Clone, Debug)]
pub struct QuoteRelationStatements {
    pub products: Vec<ProductStatement>,
    pub ranges: Vec<RangeRelationStatement>,
}

#[derive(Clone, Copy)]
struct ProductSpec {
    multiplicand: RistrettoPoint,
    factor: RistrettoPoint,
    product: RistrettoPoint,
}

fn quote_product_specs(
    circuit: &QuoteCircuit,
    statement: &QuoteNodeStatement,
    public: &Public,
) -> Result<Vec<ProductSpec>, String> {
    if statement.maker_count != public.registry.len() {
        return Err("quote relation statement has a different registry size".into());
    }
    let wire = |maker: usize, offset: usize| -> RistrettoPoint {
        statement.wires[1 + maker * LOCAL_WIRES_PER_MAKER + offset].commitment
    };
    let mut specs = Vec::with_capacity(statement.maker_count * 11);
    for maker in 0..statement.maker_count {
        let slope = wire(maker, 2);
        let invcoef = wire(maker, 3);
        let inv = wire(maker, 4);
        let active = wire(maker, 7);
        let use_ref = wire(maker, 8);
        let depth = wire(maker, 9);
        let skew = wire(maker, 10);
        let fits_value = wire(maker, 11);
        let fits_holds = wire(maker, 12);
        let fits_product = wire(maker, 13);
        let fresh_value = wire(maker, 14);
        let fresh_holds = wire(maker, 15);
        let fresh_product = wire(maker, 16);
        let both = wire(maker, 17);
        let ok = wire(maker, 18);
        let gated = wire(maker, 19);
        let cost = wire(maker, 20);
        let shifted_cost = cost - circuit.key.g * scalar(public.sentinel);
        let asset_match = Scalar::from(u64::from(
            public.registry[maker].maker_asset == public.asset,
        ));
        specs.extend([
            ProductSpec {
                multiplicand: slope,
                factor: statement.wires[0].commitment,
                product: depth,
            },
            ProductSpec {
                multiplicand: invcoef,
                factor: inv,
                product: skew,
            },
            ProductSpec {
                multiplicand: fits_holds,
                factor: fits_holds,
                product: fits_holds,
            },
            ProductSpec {
                multiplicand: fits_holds,
                factor: fits_value,
                product: fits_product,
            },
            ProductSpec {
                multiplicand: fresh_holds,
                factor: fresh_holds,
                product: fresh_holds,
            },
            ProductSpec {
                multiplicand: fresh_holds,
                factor: fresh_value,
                product: fresh_product,
            },
            ProductSpec {
                multiplicand: active,
                factor: active,
                product: active,
            },
            ProductSpec {
                multiplicand: use_ref,
                factor: use_ref,
                product: use_ref,
            },
            ProductSpec {
                multiplicand: fits_holds,
                factor: fresh_holds,
                product: both,
            },
            ProductSpec {
                multiplicand: both,
                factor: active * asset_match,
                product: ok,
            },
            ProductSpec {
                multiplicand: ok,
                factor: shifted_cost,
                product: gated,
            },
        ]);
    }
    Ok(specs)
}

impl QuoteNodeContribution {
    fn product_contributions(
        &self,
        _circuit: &QuoteCircuit,
        public: &Public,
    ) -> Result<Vec<(ProductNodeContribution, RistrettoPoint)>, String> {
        if self.makers.len() != public.registry.len() {
            return Err("bound quote node has a different registry size".into());
        }
        let mut products = Vec::with_capacity(self.makers.len() * 11);
        for (index, maker) in self.makers.iter().enumerate() {
            let asset_match = Scalar::from(u64::from(
                public.registry[index].maker_asset == public.asset,
            ));
            products.extend([
                (
                    ProductNodeContribution::new(self.qty.clone(), maker.depth_cross),
                    maker.fields.slope.commitment(),
                ),
                (
                    ProductNodeContribution::new(maker.fields.inv.clone(), maker.skew_cross),
                    maker.fields.invcoef.commitment(),
                ),
                (
                    ProductNodeContribution::new(maker.fits.holds.clone(), maker.fits.holds_cross),
                    maker.fits.holds.commitment(),
                ),
                (
                    ProductNodeContribution::new(
                        maker.fits.value.clone(),
                        maker.fits.product_cross,
                    ),
                    maker.fits.holds.commitment(),
                ),
                (
                    ProductNodeContribution::new(
                        maker.fresh.holds.clone(),
                        maker.fresh.holds_cross,
                    ),
                    maker.fresh.holds.commitment(),
                ),
                (
                    ProductNodeContribution::new(
                        maker.fresh.value.clone(),
                        maker.fresh.product_cross,
                    ),
                    maker.fresh.holds.commitment(),
                ),
                (
                    ProductNodeContribution::new(maker.fields.active.clone(), maker.active_cross),
                    maker.fields.active.commitment(),
                ),
                (
                    ProductNodeContribution::new(
                        maker.fields.use_ref.clone(),
                        maker.reference_cross,
                    ),
                    maker.fields.use_ref.commitment(),
                ),
                (
                    ProductNodeContribution::new(maker.fresh.holds.clone(), maker.both_cross),
                    maker.fits.holds.commitment(),
                ),
                (
                    ProductNodeContribution::new(
                        maker.fields.active.scaled(&asset_match),
                        maker.ok_cross,
                    ),
                    maker.both.commitment(),
                ),
                (
                    ProductNodeContribution::new(maker.shifted_cost.clone(), maker.gated_cross),
                    maker.ok.commitment(),
                ),
            ]);
        }
        Ok(products)
    }

    fn range_contributions(&self) -> Vec<&NodeValueShares> {
        let mut ranges = Vec::with_capacity(self.makers.len() * LOCAL_RANGES_PER_MAKER);
        for (maker, minimum) in self.makers.iter().zip(&self.minimality) {
            ranges.extend([&maker.fits.bits, &maker.fresh.bits, minimum]);
        }
        ranges
    }

    pub fn relation_evaluations(
        &self,
        circuit: &QuoteCircuit,
        public: &Public,
    ) -> Result<QuoteRelationEvaluations, String> {
        Ok(QuoteRelationEvaluations {
            party: self.party,
            products: self
                .product_contributions(circuit, public)?
                .into_iter()
                .map(|(product, multiplicand)| product.evaluations(&circuit.key, &multiplicand))
                .collect(),
            ranges: self
                .range_contributions()
                .into_iter()
                .map(|range| range.relation_evaluations(&circuit.key))
                .collect(),
        })
    }
}

pub fn quote_relation_statements_from_evaluations(
    circuit: &QuoteCircuit,
    statement: &QuoteNodeStatement,
    public: &Public,
    evaluations: &[QuoteRelationEvaluations],
) -> Result<QuoteRelationStatements, String> {
    let specs = quote_product_specs(circuit, statement, public)?;
    if evaluations.len() < statement.threshold + 1 {
        return Err("too few quote relation evaluations".into());
    }
    let expected_ranges = statement.maker_count * LOCAL_RANGES_PER_MAKER;
    let mut seen = std::collections::BTreeSet::new();
    for node in evaluations {
        if !seen.insert(node.party)
            || !statement.parties.contains(&node.party)
            || node.products.len() != specs.len()
            || node.ranges.len() != expected_ranges
            || node.products.iter().any(|value| value.party != node.party)
            || node.ranges.iter().any(|value| value.party != node.party)
        {
            return Err("quote relation evaluations have different shapes or parties".into());
        }
    }
    let mut products = Vec::with_capacity(specs.len());
    for (index, spec) in specs.iter().enumerate() {
        products.push(product_statement_from_evaluations(
            &spec.multiplicand,
            &spec.factor,
            &spec.product,
            &evaluations
                .iter()
                .map(|node| node.products[index].clone())
                .collect::<Vec<_>>(),
            statement.threshold,
        )?);
    }
    let mut ranges = Vec::with_capacity(expected_ranges);
    for index in 0..expected_ranges {
        ranges.push(range_relations_from_evaluations(
            &statement.ranges[index],
            &evaluations
                .iter()
                .map(|node| node.ranges[index].clone())
                .collect::<Vec<_>>(),
        )?);
    }
    Ok(QuoteRelationStatements { products, ranges })
}

const PRODUCTS_PER_MAKER: usize = 11;

fn product_round_context(proof_context: &[u8; 32], maker: usize, component: usize) -> Vec<u8> {
    let mut out = b"QOMM:QUOTE:PRODUCT-ROUND:v1".to_vec();
    out.extend_from_slice(proof_context);
    out.extend_from_slice(&(maker as u64).to_be_bytes());
    out.extend_from_slice(&(component as u64).to_be_bytes());
    out
}

fn quote_product_transcript(
    proof_context: &[u8; 32],
    maker: usize,
    component: usize,
) -> Result<Transcript, String> {
    let tagged = |name: &str| QuoteCircuit::tag(proof_context, maker, name);
    let gate = |name: &[u8], label: &'static [u8]| {
        let context = QuoteCircuit::gate_context(proof_context, maker, name);
        let mut transcript = Transcript::new(label);
        transcript.append_message(b"ctx", &context);
        transcript
    };
    match component {
        0 => Ok(tagged("depth")),
        1 => Ok(tagged("skew")),
        2 => Ok(gate(b"fits", b"qomm:quote:gate:bit")),
        3 => Ok(gate(b"fits", b"qomm:quote:gate:prod")),
        4 => Ok(gate(b"fresh", b"qomm:quote:gate:bit")),
        5 => Ok(gate(b"fresh", b"qomm:quote:gate:prod")),
        6 => Ok(tagged("active")),
        7 => Ok(tagged("reference")),
        8 => Ok(tagged("ok1")),
        9 => Ok(tagged("ok2")),
        10 => Ok(tagged("gate")),
        _ => Err("quote product component is outside its fixed layout".into()),
    }
}

fn quote_range_context(
    proof_context: &[u8; 32],
    maker: usize,
    component: usize,
) -> Result<Vec<u8>, String> {
    match component {
        0 => Ok(QuoteCircuit::gate_range_context(
            proof_context,
            maker,
            b"fits",
        )),
        1 => Ok(QuoteCircuit::gate_range_context(
            proof_context,
            maker,
            b"fresh",
        )),
        2 => Ok(QuoteCircuit::minimality_context(proof_context, maker)),
        _ => Err("quote range component is outside its fixed layout".into()),
    }
}

fn winner_round_context(proof_context: &[u8; 32]) -> Vec<u8> {
    let mut out = b"QOMM:QUOTE:WINNER-ROUND:v1".to_vec();
    out.extend_from_slice(proof_context);
    out
}

fn winner_statement(
    circuit: &QuoteCircuit,
    statement: &QuoteNodeStatement,
) -> Result<WireStatement, String> {
    let source = statement
        .wires
        .get(1 + statement.winner_index * LOCAL_WIRES_PER_MAKER + 21)
        .ok_or("winner key is outside the quote statement")?;
    let shift = circuit.key.g * Scalar::from(statement.winner_value);
    let mut coefficients = source.coefficient_commitments.clone();
    let constant = coefficients
        .first_mut()
        .ok_or("winner key has an empty VSS ladder")?;
    *constant -= shift;
    Ok(WireStatement {
        commitment: source.commitment - shift,
        coefficient_commitments: coefficients,
        threshold: source.threshold,
    })
}

#[derive(Clone, Debug)]
pub struct QuoteRound1Seals {
    pub party: PartyId,
    pub products: Vec<ProductRound1Seal>,
    pub ranges: Vec<RangeRound1Seal>,
    pub winner: OpeningRound1Seal,
}

#[derive(Clone, Debug)]
pub struct QuoteRound1 {
    pub party: PartyId,
    pub products: Vec<ProductRound1>,
    pub ranges: Vec<RangeRound1>,
    pub winner: OpeningRound1,
}

pub struct QuoteRound1Secrets {
    party: PartyId,
    products: Vec<ProductRound1Secret>,
    ranges: Vec<RangeRound1Secret>,
    winner: OpeningRound1Secret,
}

#[derive(Clone, Debug)]
pub struct QuoteChallenges {
    pub products: Vec<ProductChallenge>,
    pub ranges: Vec<RangeChallenge>,
    pub winner: OpeningChallenge,
}

#[derive(Clone, Debug)]
pub struct QuoteRound2 {
    pub party: PartyId,
    pub products: Vec<ProductRound2>,
    pub ranges: Vec<RangeRound2>,
    pub winner: OpeningRound2,
}

impl QuoteNodeContribution {
    fn winner_contribution(
        &self,
        circuit: &QuoteCircuit,
    ) -> Result<OpeningNodeContribution, String> {
        let winner = self
            .key_wires
            .get(self.winner_index)
            .ok_or("winner index is outside the node's key vector")?
            .shifted(&circuit.key, &-Scalar::from(self.winner_value));
        let (value, blinding) = winner.own_evaluation();
        Ok(OpeningNodeContribution::new(self.party, value, blinding))
    }

    pub fn prepare_round1<R: RngCore + CryptoRng>(
        &self,
        circuit: &QuoteCircuit,
        public: &Public,
        context: &[u8],
        rng: &mut R,
    ) -> Result<(QuoteRound1Seals, QuoteRound1Secrets, QuoteRound1), String> {
        let proof_context = QuoteCircuit::statement_context(context, public);
        let products = self.product_contributions(circuit, public)?;
        let mut product_seals = Vec::with_capacity(products.len());
        let mut product_secrets = Vec::with_capacity(products.len());
        let mut product_rounds = Vec::with_capacity(products.len());
        for (index, (product, multiplicand)) in products.iter().enumerate() {
            let maker = index / PRODUCTS_PER_MAKER;
            let component = index % PRODUCTS_PER_MAKER;
            let round_context = product_round_context(&proof_context, maker, component);
            let (seal, secret, round) = prepare_product_round1(
                &circuit.key,
                product,
                multiplicand,
                &round_context,
                &mut *rng,
            );
            product_seals.push(seal);
            product_secrets.push(secret);
            product_rounds.push(round);
        }
        let ranges = self.range_contributions();
        let mut range_seals = Vec::with_capacity(ranges.len());
        let mut range_secrets = Vec::with_capacity(ranges.len());
        let mut range_rounds = Vec::with_capacity(ranges.len());
        for (index, range) in ranges.iter().enumerate() {
            let maker = index / LOCAL_RANGES_PER_MAKER;
            let component = index % LOCAL_RANGES_PER_MAKER;
            let range_context = quote_range_context(&proof_context, maker, component)?;
            let (seal, secret, round) =
                prepare_range_round1(&circuit.key, range, &range_context, &mut *rng);
            range_seals.push(seal);
            range_secrets.push(secret);
            range_rounds.push(round);
        }
        let winner = self.winner_contribution(circuit)?;
        let winner_context = winner_round_context(&proof_context);
        let (winner_seal, winner_secret, winner_round) =
            prepare_opening_round1(&circuit.key, &winner, &winner_context, &mut *rng);
        Ok((
            QuoteRound1Seals {
                party: self.party,
                products: product_seals,
                ranges: range_seals,
                winner: winner_seal,
            },
            QuoteRound1Secrets {
                party: self.party,
                products: product_secrets,
                ranges: range_secrets,
                winner: winner_secret,
            },
            QuoteRound1 {
                party: self.party,
                products: product_rounds,
                ranges: range_rounds,
                winner: winner_round,
            },
        ))
    }

    pub fn answer_round1(
        &self,
        circuit: &QuoteCircuit,
        public: &Public,
        secrets: QuoteRound1Secrets,
        challenges: &QuoteChallenges,
    ) -> Result<QuoteRound2, String> {
        if secrets.party != self.party {
            return Err("quote round-one secrets belong to another node".into());
        }
        let products = self.product_contributions(circuit, public)?;
        let ranges = self.range_contributions();
        if products.len() != secrets.products.len()
            || products.len() != challenges.products.len()
            || ranges.len() != secrets.ranges.len()
            || ranges.len() != challenges.ranges.len()
        {
            return Err("quote challenge has a different relation layout".into());
        }
        let product_answers = products
            .into_iter()
            .zip(secrets.products)
            .zip(&challenges.products)
            .map(|(((product, _), secret), challenge)| {
                answer_product_challenge(&product, secret, challenge)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let range_answers = ranges
            .into_iter()
            .zip(secrets.ranges)
            .zip(&challenges.ranges)
            .map(|((range, secret), challenge)| answer_range_challenge(range, secret, challenge))
            .collect::<Result<Vec<_>, _>>()?;
        let winner = self.winner_contribution(circuit)?;
        let winner_answer = answer_opening_challenge(&winner, secrets.winner, &challenges.winner)?;
        Ok(QuoteRound2 {
            party: self.party,
            products: product_answers,
            ranges: range_answers,
            winner: winner_answer,
        })
    }
}

fn check_quote_round_parties<T>(
    values: &[(PartyId, T)],
    quorum: &[PartyId],
    what: &str,
) -> Result<(), String> {
    let parties = values
        .iter()
        .map(|(party, _)| *party)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = quorum
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if values.len() != quorum.len() || parties != expected {
        return Err(format!("{what} do not exactly match the quote quorum"));
    }
    Ok(())
}

pub struct QuoteChallengeTranscript<'a> {
    pub rounds: &'a [QuoteRound1],
    pub seals: &'a [QuoteRound1Seals],
    pub quorum: &'a [PartyId],
    pub context: &'a [u8],
}

pub fn make_quote_challenges(
    circuit: &QuoteCircuit,
    statement: &QuoteNodeStatement,
    relations: &QuoteRelationStatements,
    public: &Public,
    transcript: QuoteChallengeTranscript<'_>,
) -> Result<QuoteChallenges, String> {
    let QuoteChallengeTranscript {
        rounds,
        seals,
        quorum,
        context,
    } = transcript;
    check_quote_round_parties(
        &rounds
            .iter()
            .map(|value| (value.party, ()))
            .collect::<Vec<_>>(),
        quorum,
        "quote round-one messages",
    )?;
    check_quote_round_parties(
        &seals
            .iter()
            .map(|value| (value.party, ()))
            .collect::<Vec<_>>(),
        quorum,
        "quote round-one seals",
    )?;
    let product_count = statement.maker_count * PRODUCTS_PER_MAKER;
    let range_count = statement.maker_count * LOCAL_RANGES_PER_MAKER;
    if relations.products.len() != product_count
        || relations.ranges.len() != range_count
        || rounds
            .iter()
            .any(|round| round.products.len() != product_count || round.ranges.len() != range_count)
        || seals
            .iter()
            .any(|seal| seal.products.len() != product_count || seal.ranges.len() != range_count)
    {
        return Err("quote proof rounds have different relation layouts".into());
    }
    let proof_context = QuoteCircuit::statement_context(context, public);
    let mut product_challenges = Vec::with_capacity(product_count);
    for index in 0..product_count {
        let maker = index / PRODUCTS_PER_MAKER;
        let component = index % PRODUCTS_PER_MAKER;
        let round_context = product_round_context(&proof_context, maker, component);
        let mut transcript = quote_product_transcript(&proof_context, maker, component)?;
        product_challenges.push(make_product_challenge_with_transcript(
            &relations.products[index],
            &rounds
                .iter()
                .map(|node| node.products[index].clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.products[index].clone())
                .collect::<Vec<_>>(),
            quorum,
            &round_context,
            &mut transcript,
        )?);
    }
    let mut range_challenges = Vec::with_capacity(range_count);
    for index in 0..range_count {
        let maker = index / LOCAL_RANGES_PER_MAKER;
        let component = index % LOCAL_RANGES_PER_MAKER;
        let range_context = quote_range_context(&proof_context, maker, component)?;
        range_challenges.push(make_range_challenge(
            &statement.ranges[index],
            &rounds
                .iter()
                .map(|node| node.ranges[index].clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.ranges[index].clone())
                .collect::<Vec<_>>(),
            quorum,
            &range_context,
        )?);
    }
    let winner = winner_statement(circuit, statement)?;
    let winner_context = winner_round_context(&proof_context);
    let mut winner_transcript = QuoteCircuit::whole(&proof_context, "winner");
    let winner_challenge = make_opening_challenge_with_transcript(
        &winner.commitment,
        &rounds
            .iter()
            .map(|node| node.winner.clone())
            .collect::<Vec<_>>(),
        &seals
            .iter()
            .map(|node| node.winner.clone())
            .collect::<Vec<_>>(),
        quorum,
        &winner_context,
        &mut winner_transcript,
    )?;
    Ok(QuoteChallenges {
        products: product_challenges,
        ranges: range_challenges,
        winner: winner_challenge,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_quote_from_rounds(
    circuit: &QuoteCircuit,
    statement: &QuoteNodeStatement,
    relations: &QuoteRelationStatements,
    public: &Public,
    rounds: &[QuoteRound1],
    seals: &[QuoteRound1Seals],
    responses: &[QuoteRound2],
    quorum: &[PartyId],
    context: &[u8],
) -> Result<QuoteProof, String> {
    let challenges = make_quote_challenges(
        circuit,
        statement,
        relations,
        public,
        QuoteChallengeTranscript {
            rounds,
            seals,
            quorum,
            context,
        },
    )?;
    check_quote_round_parties(
        &responses
            .iter()
            .map(|value| (value.party, ()))
            .collect::<Vec<_>>(),
        quorum,
        "quote round-two responses",
    )?;
    if responses.iter().any(|response| {
        response.products.len() != challenges.products.len()
            || response.ranges.len() != challenges.ranges.len()
    }) {
        return Err("quote round-two responses have different relation layouts".into());
    }
    let proof_context = QuoteCircuit::statement_context(context, public);
    let mut product_proofs = Vec::with_capacity(challenges.products.len());
    for index in 0..challenges.products.len() {
        let maker = index / PRODUCTS_PER_MAKER;
        let component = index % PRODUCTS_PER_MAKER;
        let round_context = product_round_context(&proof_context, maker, component);
        let mut transcript = quote_product_transcript(&proof_context, maker, component)?;
        product_proofs.push(assemble_product_from_rounds_with_transcript(
            &circuit.key,
            &relations.products[index],
            &rounds
                .iter()
                .map(|node| node.products[index].clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.products[index].clone())
                .collect::<Vec<_>>(),
            &responses
                .iter()
                .map(|node| node.products[index].clone())
                .collect::<Vec<_>>(),
            quorum,
            &round_context,
            &mut transcript,
        )?);
    }
    let mut range_proofs = Vec::with_capacity(challenges.ranges.len());
    for index in 0..challenges.ranges.len() {
        let maker = index / LOCAL_RANGES_PER_MAKER;
        let component = index % LOCAL_RANGES_PER_MAKER;
        let range_context = quote_range_context(&proof_context, maker, component)?;
        range_proofs.push(assemble_range_from_rounds(
            &circuit.key,
            &statement.ranges[index],
            &relations.ranges[index],
            &rounds
                .iter()
                .map(|node| node.ranges[index].clone())
                .collect::<Vec<_>>(),
            &seals
                .iter()
                .map(|node| node.ranges[index].clone())
                .collect::<Vec<_>>(),
            &responses
                .iter()
                .map(|node| node.ranges[index].clone())
                .collect::<Vec<_>>(),
            quorum,
            &range_context,
        )?);
    }
    let winner = winner_statement(circuit, statement)?;
    let winner_context = winner_round_context(&proof_context);
    let mut winner_transcript = QuoteCircuit::whole(&proof_context, "winner");
    let winner_opening = assemble_opening_from_rounds_with_transcript(
        &circuit.key,
        &winner.commitment,
        &winner.coefficient_commitments,
        &rounds
            .iter()
            .map(|node| node.winner.clone())
            .collect::<Vec<_>>(),
        &seals
            .iter()
            .map(|node| node.winner.clone())
            .collect::<Vec<_>>(),
        &responses
            .iter()
            .map(|node| node.winner.clone())
            .collect::<Vec<_>>(),
        quorum,
        &winner_context,
        &mut winner_transcript,
    )?;
    let wire = |maker: usize, offset: usize| -> RistrettoPoint {
        statement.wires[1 + maker * LOCAL_WIRES_PER_MAKER + offset].commitment
    };
    let mut maker_proofs = Vec::with_capacity(statement.maker_count);
    let mut minimality = Vec::with_capacity(statement.maker_count);
    let mut key_commitments = Vec::with_capacity(statement.maker_count);
    for maker in 0..statement.maker_count {
        let product = maker * PRODUCTS_PER_MAKER;
        let range = maker * LOCAL_RANGES_PER_MAKER;
        let fits_holds = wire(maker, 12);
        let fits_product = wire(maker, 13);
        let fresh_holds = wire(maker, 15);
        let fresh_product = wire(maker, 16);
        let cost = wire(maker, 20);
        maker_proofs.push(MakerProof {
            depth: product_proofs[product].clone(),
            skew: product_proofs[product + 1].clone(),
            gate_cost: product_proofs[product + 10].clone(),
            eligibility: EligibilityProof::Threshold {
                fits: Box::new(range_proofs[range].clone()),
                fresh: Box::new(range_proofs[range + 1].clone()),
            },
            active_bit: BitValidityProof::Square(product_proofs[product + 6].clone()),
            reference_bit: BitValidityProof::Square(product_proofs[product + 7].clone()),
            fits_gate: Gate {
                commitment: fits_holds,
                bit_proof: BitValidityProof::Square(product_proofs[product + 2].clone()),
                product: product_proofs[product + 3].clone(),
                product_commitment: fits_product,
                witness_commitment: statement.ranges[range].commitment,
            },
            fresh_gate: Gate {
                commitment: fresh_holds,
                bit_proof: BitValidityProof::Square(product_proofs[product + 4].clone()),
                product: product_proofs[product + 5].clone(),
                product_commitment: fresh_product,
                witness_commitment: statement.ranges[range + 1].commitment,
            },
            conjunction: (
                product_proofs[product + 8].clone(),
                product_proofs[product + 9].clone(),
            ),
            commitments: MakerCommitments {
                slope: wire(maker, 2),
                invcoef: wire(maker, 3),
                inv: wire(maker, 4),
                depth: wire(maker, 9),
                skew: wire(maker, 10),
                fits: wire(maker, 11),
                fresh: wire(maker, 6) - circuit.key.g * scalar(public.now),
                active: wire(maker, 7),
                ok: wire(maker, 18),
                fresh_strict: wire(maker, 14),
                both: wire(maker, 17),
                cost,
                gated: wire(maker, 19),
                shifted_cost: cost - circuit.key.g * scalar(public.sentinel),
            },
        });
        minimality.push(range_proofs[range + 2].clone());
        key_commitments.push(wire(maker, 21));
    }
    let proof = QuoteProof {
        winner_index: statement.winner_index,
        winner_value: statement.winner_value,
        maker_proofs,
        winner_opening,
        minimality: MinimalityProof::Threshold(minimality),
        key_commitments,
    };
    circuit
        .verify(&proof, public, context)
        .map_err(|error| format!("assembled distributed quote proof is invalid: {error:?}"))?;
    Ok(proof)
}

fn node_policy(source: &DealerPolicyShares, party: PartyId) -> Result<NodePolicyShares, String> {
    let get = |wire: &Shared, name: &str| {
        wire.node_share(party)
            .ok_or_else(|| format!("{name} omitted party {party}"))
    };
    Ok(NodePolicyShares {
        ask_level: get(&source.ask_level, "ask level")?,
        spread: get(&source.spread, "spread")?,
        slope: get(&source.slope, "slope")?,
        invcoef: get(&source.invcoef, "inventory coefficient")?,
        inv: get(&source.inv, "inventory")?,
        maxqty: get(&source.maxqty, "maximum quantity")?,
        expiry: get(&source.expiry, "expiry")?,
        active: get(&source.active, "active")?,
        use_ref: get(&source.use_ref, "reference flag")?,
    })
}

fn node_gate(source: &DealerGateShares, party: PartyId) -> Result<NodeGateShares, String> {
    Ok(NodeGateShares {
        value: source
            .value
            .node_share(party)
            .ok_or_else(|| format!("gate value omitted party {party}"))?,
        holds: source
            .holds
            .node_share(party)
            .ok_or_else(|| format!("gate bit omitted party {party}"))?,
        holds_cross: *source
            .holds_cross
            .get(&party)
            .ok_or_else(|| format!("gate bit cross term omitted party {party}"))?,
        product: source
            .product
            .node_share(party)
            .ok_or_else(|| format!("gate product omitted party {party}"))?,
        product_cross: *source
            .product_cross
            .get(&party)
            .ok_or_else(|| format!("gate product cross term omitted party {party}"))?,
        witness: source
            .witness
            .node_share(party)
            .ok_or_else(|| format!("gate witness omitted party {party}"))?,
        bits: source
            .bits
            .node_contribution(party)
            .ok_or_else(|| format!("gate range omitted party {party}"))?,
    })
}

fn node_maker(source: &DealerMakerShares, party: PartyId) -> Result<NodeMakerShares, String> {
    let get = |wire: &Shared, name: &str| {
        wire.node_share(party)
            .ok_or_else(|| format!("{name} omitted party {party}"))
    };
    let cross = |shares: &ScalarShares, name: &str| {
        shares
            .get(&party)
            .copied()
            .ok_or_else(|| format!("{name} omitted party {party}"))
    };
    Ok(NodeMakerShares {
        fields: node_policy(&source.fields, party)?,
        depth: get(&source.depth, "depth")?,
        depth_cross: cross(&source.depth_cross, "depth cross term")?,
        skew: get(&source.skew, "skew")?,
        skew_cross: cross(&source.skew_cross, "skew cross term")?,
        fits: node_gate(&source.fits, party)?,
        fresh: node_gate(&source.fresh, party)?,
        active_cross: cross(&source.active_cross, "active cross term")?,
        reference_cross: cross(&source.reference_cross, "reference cross term")?,
        both: get(&source.both, "both")?,
        both_cross: cross(&source.both_cross, "both cross term")?,
        ok: get(&source.ok, "ok")?,
        ok_cross: cross(&source.ok_cross, "ok cross term")?,
        gated: get(&source.gated, "gated")?,
        gated_cross: cross(&source.gated_cross, "gated cross term")?,
        cost: get(&source.cost, "cost")?,
        shifted_cost: get(&source.shifted_cost, "shifted cost")?,
        packed: get(&source.packed, "packed key")?,
    })
}

fn gate<R: RngCore + CryptoRng>(
    dealer: &mut Dealer<'_, R>,
    value: Shared,
    actual: i64,
    width: usize,
) -> Result<DealerGateShares, String> {
    let holds_value = actual >= 0;
    let holds_scalar = Scalar::from(u64::from(holds_value));
    let holds_blinding = dealer.random_scalar();
    let holds = dealer.wire(i64::from(holds_value), holds_blinding)?;

    let product_value = if holds_value { actual } else { 0 };
    let product_blinding = dealer.random_scalar();
    let product = dealer.wire(product_value, product_blinding)?;
    let witness_value =
        i128::from(product_value) * 2 - i128::from(actual) + i128::from(i64::from(holds_value)) - 1;
    let witness_value =
        i64::try_from(witness_value).map_err(|_| "eligibility witness overflow".to_string())?;
    let witness = shift(
        dealer.key,
        &add(&sub(&scale(&product, &Scalar::from(2u64)), &value)?, &holds)?,
        &-Scalar::ONE,
    );
    let holds_cross = dealer.square_cross(&holds_blinding, holds_value)?;
    let product_cross = dealer.cross(&product_blinding, &holds_blinding, &scalar(actual))?;
    let bits = bits_for(
        dealer.key,
        &witness,
        scalar_to_u64(witness_value, "eligibility witness went negative")?,
        width,
        dealer.parties,
        dealer.threshold,
        &mut *dealer.rng,
    )?;
    // Keep the exact field equation visible at the handoff boundary.
    debug_assert_eq!(
        witness.commitment.compress(),
        (product.commitment + product.commitment - value.commitment + holds.commitment
            - dealer.key.g)
            .compress()
    );
    let _ = holds_scalar;
    Ok(DealerGateShares {
        value,
        holds,
        holds_cross,
        product,
        product_cross,
        witness,
        bits,
        holds_blinding,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn deal_quote_shares<R: RngCore + CryptoRng>(
    circuit: &QuoteCircuit,
    makers: &[MakerWitness],
    qty: i64,
    direction: u8,
    now: i64,
    sentinel: i64,
    n_slots: i64,
    parties: &[PartyId],
    threshold: usize,
    market_digest: [u8; 32],
    slot: u64,
    rng: &mut R,
) -> Result<(Vec<QuoteNodeContribution>, Public), String> {
    let qty_blinding = Scalar::random(&mut *rng);
    deal_quote_shares_with_qty_blinding(
        circuit,
        makers,
        qty,
        qty_blinding,
        direction,
        now,
        sentinel,
        n_slots,
        parties,
        threshold,
        market_digest,
        slot,
        rng,
    )
}

/// Deal the quote circuit while reusing the Taker's committed quantity
/// blinding. The complete quote proof and the eventual zkPI must expose the
/// same quantity commitment; generating an unrelated blinding here would make
/// that binding unverifiable even when both hidden values are numerically
/// equal.
#[allow(clippy::too_many_arguments)]
pub fn deal_quote_shares_with_qty_blinding<R: RngCore + CryptoRng>(
    circuit: &QuoteCircuit,
    makers: &[MakerWitness],
    qty: i64,
    qty_blinding: Scalar,
    direction: u8,
    now: i64,
    sentinel: i64,
    n_slots: i64,
    parties: &[PartyId],
    threshold: usize,
    market_digest: [u8; 32],
    slot: u64,
    rng: &mut R,
) -> Result<(Vec<QuoteNodeContribution>, Public), String> {
    if makers.is_empty() {
        return Err("a quote needs at least one registered maker".into());
    }
    if direction > 1 {
        return Err("direction must be 0 (buy) or 1 (sell)".into());
    }
    if n_slots <= 0
        || usize::try_from(n_slots)
            .ok()
            .is_none_or(|slots| slots < makers.len())
    {
        return Err("n_slots must provide a distinct low slot for every maker".into());
    }
    if parties.len() <= threshold {
        return Err(format!(
            "{} parties cannot support threshold {threshold}; at least {} are required",
            parties.len(),
            threshold + 1
        ));
    }
    if makers.iter().any(|maker| !maker.blindings.is_registered()) {
        return Err("a maker has no registered blindings: a quote proof is about policies that were put on the record, and a witness without them is a policy invented now".into());
    }

    let key = &circuit.key;
    let mut dealer = Dealer {
        key,
        parties,
        threshold,
        rng,
    };
    let qty_shared = dealer.wire(qty, qty_blinding)?;
    let mut maker_shares = Vec::with_capacity(makers.len());
    let mut keys = Vec::with_capacity(makers.len());
    let mut key_wires = Vec::with_capacity(makers.len());

    for (index, maker) in makers.iter().enumerate() {
        let Registered {
            ask_level: r_ask_level,
            spread: r_spread,
            slope: r_slope,
            invcoef: r_invcoef,
            inv: r_inv,
            maxqty: r_maxqty,
            expiry: r_expiry,
            active: r_active,
        } = maker.blindings;
        let fields = DealerPolicyShares {
            ask_level: dealer.wire(maker.ask_level, r_ask_level)?,
            spread: dealer.wire(maker.spread, r_spread)?,
            slope: dealer.wire(maker.slope, r_slope)?,
            invcoef: dealer.wire(maker.invcoef, r_invcoef)?,
            inv: dealer.wire(maker.inv, r_inv)?,
            maxqty: dealer.wire(maker.maxqty, r_maxqty)?,
            expiry: dealer.wire(maker.expiry, r_expiry)?,
            active: dealer.wire(i64::from(maker.active), r_active)?,
            use_ref: dealer.wire(0, Scalar::ZERO)?,
        };

        let depth_value = checked_mul(maker.slope, qty, "depth overflow")?;
        let depth_blinding = dealer.random_scalar();
        let depth = dealer.wire(depth_value, depth_blinding)?;
        let depth_cross = dealer.cross(&depth_blinding, &r_slope, &scalar(qty))?;

        let skew_value = checked_mul(maker.invcoef, maker.inv, "inventory skew overflow")?;
        let skew_blinding = dealer.random_scalar();
        let skew = dealer.wire(skew_value, skew_blinding)?;
        let skew_cross = dealer.cross(&skew_blinding, &r_invcoef, &scalar(maker.inv))?;

        let fits_value = checked_sub(maker.maxqty, qty, "size margin overflow")?;
        let fits_wire = sub(&fields.maxqty, &qty_shared)?;
        let fits = gate(
            &mut dealer,
            fits_wire,
            fits_value,
            circuit.eligibility_bits() + 2,
        )?;
        let fresh = checked_sub(maker.expiry, now, "expiry margin overflow")?;
        let fresh_value = checked_sub(fresh, 1, "strict expiry overflow")?;
        let fresh_wire = shift(
            key,
            &fields.expiry,
            &-scalar(checked_add(now, 1, "strict expiry overflow")?),
        );
        let fresh = gate(
            &mut dealer,
            fresh_wire,
            fresh_value,
            circuit.eligibility_bits() + 2,
        )?;

        let both_value = fits_value >= 0 && fresh_value >= 0;
        let both_blinding = dealer.random_scalar();
        let both = dealer.wire(i64::from(both_value), both_blinding)?;
        let both_cross = dealer.cross(
            &both_blinding,
            &fits.holds_blinding,
            &Scalar::from(u64::from(fresh_value >= 0)),
        )?;

        let ok_value = both_value && maker.active;
        let ok_blinding = dealer.random_scalar();
        let ok = dealer.wire(i64::from(ok_value), ok_blinding)?;
        let ok_cross = dealer.cross(
            &ok_blinding,
            &both_blinding,
            &Scalar::from(u64::from(maker.active)),
        )?;
        let active_cross = dealer.square_cross(&r_active, maker.active)?;
        let reference_cross = dealer.square_cross(&Scalar::ZERO, false)?;

        let ask = checked_add(
            checked_add(maker.ask_level, depth_value, "ask price overflow")?,
            skew_value,
            "ask price overflow",
        )?;
        let bid = checked_add(
            checked_sub(
                checked_sub(maker.ask_level, maker.spread, "bid price overflow")?,
                depth_value,
                "bid price overflow",
            )?,
            skew_value,
            "bid price overflow",
        )?;
        let ask_wire = add(&add(&fields.ask_level, &depth)?, &skew)?;
        let bid_wire = add(
            &sub(&sub(&fields.ask_level, &fields.spread)?, &depth)?,
            &skew,
        )?;
        let (cost_value, cost) = if direction == 1 {
            (
                bid.checked_neg()
                    .ok_or_else(|| "sell cost overflow".to_string())?,
                negate(&bid_wire),
            )
        } else {
            (ask, ask_wire)
        };
        let shifted_cost_value = checked_sub(cost_value, sentinel, "shifted cost overflow")?;
        let shifted_cost = shift(key, &cost, &-scalar(sentinel));

        let gated_value = if ok_value { shifted_cost_value } else { 0 };
        let gated_blinding = dealer.random_scalar();
        let gated = dealer.wire(gated_value, gated_blinding)?;
        let gated_cross =
            dealer.cross(&gated_blinding, &ok_blinding, &scalar(shifted_cost_value))?;

        let effective = checked_add(gated_value, sentinel, "effective cost overflow")?;
        let ranked = checked_add(effective, sentinel, "ranked cost overflow")?;
        let packed_value = checked_add(
            checked_mul(ranked, n_slots, "packed key overflow")?,
            i64::try_from(index).map_err(|_| "maker index does not fit i64")?,
            "packed key overflow",
        )?;
        if packed_value < 0 {
            return Err("the sentinel does not cover the signed quote cost".into());
        }
        let packed = shift(
            key,
            &scale(&gated, &scalar(n_slots)),
            &scalar(checked_add(
                checked_mul(
                    checked_mul(sentinel, 2, "packed key overflow")?,
                    n_slots,
                    "packed key overflow",
                )?,
                i64::try_from(index).map_err(|_| "maker index does not fit i64")?,
                "packed key overflow",
            )?),
        );
        keys.push(packed_value as u64);
        key_wires.push(packed.clone());
        maker_shares.push(DealerMakerShares {
            fields,
            depth,
            depth_cross,
            skew,
            skew_cross,
            fits,
            fresh,
            active_cross,
            reference_cross,
            both,
            both_cross,
            ok,
            ok_cross,
            gated,
            gated_cross,
            cost,
            shifted_cost,
            packed,
        });
    }

    let winner_index = (0..keys.len())
        .min_by_key(|index| keys[*index])
        .ok_or_else(|| "no makers".to_string())?;
    let winner_value = keys[winner_index];
    let mut minimality = Vec::with_capacity(keys.len());
    for index in 0..keys.len() {
        let difference = sub(&key_wires[index], &key_wires[winner_index])?;
        minimality.push(bits_for(
            key,
            &difference,
            keys[index] - winner_value,
            circuit.span_bits(),
            parties,
            threshold,
            &mut *dealer.rng,
        )?);
    }

    let registry: Vec<RegisteredPolicy> =
        makers.iter().map(|maker| maker.registered(key)).collect();
    let public = Public {
        qty_commitment: qty_shared.commitment,
        now,
        sentinel,
        n_slots,
        direction,
        asset: 0,
        reference_price: 0,
        registry_digest: registry_digest(&registry),
        registry,
        market_digest,
        slot,
    };
    let dealer_output = DealerQuoteShares {
        qty: qty_shared,
        makers: maker_shares,
        winner_index,
        winner_value,
        minimality,
        key_wires,
        threshold,
        parties: parties.to_vec(),
    };
    let node_contributions = dealer_output.node_contributions()?;
    Ok((node_contributions, public))
}

#[derive(Clone, Debug)]
pub struct QuoteAssemblyTranscript {
    pub quorum: Vec<PartyId>,
    pub product_partials: Vec<(String, ProductAssemblyTranscript)>,
    pub range_partials: Vec<(String, RangeAssemblyTranscript)>,
    pub winner_partials: OpeningAssemblyTranscript,
}

fn quote_quorum<'a>(
    contributions: &'a [QuoteNodeContribution],
    quorum: &[PartyId],
) -> Result<Vec<&'a QuoteNodeContribution>, String> {
    let indexed = contributions
        .iter()
        .map(|contribution| (contribution.party, contribution))
        .collect::<BTreeMap<_, _>>();
    if indexed.len() != contributions.len() {
        return Err("a party supplied more than one quote contribution".into());
    }
    let selected = quorum
        .iter()
        .map(|party| {
            indexed
                .get(party)
                .copied()
                .ok_or_else(|| format!("missing quote contribution from party {party}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let first = selected
        .first()
        .ok_or("a quote assembly needs at least one contribution")?;
    if quorum.len() < first.threshold + 1 {
        return Err(format!(
            "{} contributions cannot assemble threshold {}; {} are required",
            quorum.len(),
            first.threshold,
            first.threshold + 1
        ));
    }
    let first_wires = first.shared_wires();
    for node in &selected {
        if node.threshold != first.threshold
            || node.parties != first.parties
            || node.makers.len() != first.makers.len()
            || node.winner_index != first.winner_index
            || node.winner_value != first.winner_value
            || node.key_wires.len() != first.key_wires.len()
            || node.minimality.len() != first.minimality.len()
        {
            return Err(format!(
                "party {} supplied a different quote layout",
                node.party
            ));
        }
        let wires = node.shared_wires();
        if wires.len() != first_wires.len()
            || wires.iter().zip(&first_wires).any(|(wire, expected)| {
                wire.commitment().compress() != expected.commitment().compress()
                    || wire
                        .coefficient_commitments()
                        .iter()
                        .map(|point| point.compress())
                        .ne(expected
                            .coefficient_commitments()
                            .iter()
                            .map(|point| point.compress()))
            })
        {
            return Err(format!(
                "party {} supplied different public wire commitments",
                node.party
            ));
        }
    }
    Ok(selected)
}

#[allow(clippy::too_many_arguments)]
fn joint_gate_from_contributions<R: RngCore + CryptoRng>(
    circuit: &QuoteCircuit,
    gates: &[&NodeGateShares],
    quorum: &[PartyId],
    threshold: usize,
    proof_context: &[u8],
    maker_index: usize,
    name: &[u8],
    rng: &mut R,
    products: &mut Vec<(String, ProductAssemblyTranscript)>,
    ranges: &mut Vec<(String, RangeAssemblyTranscript)>,
) -> Result<(Gate, ThresholdRangeProof), String> {
    let first = gates.first().ok_or("a gate needs node contributions")?;
    let context = QuoteCircuit::gate_context(proof_context, maker_index, name);
    let bit_contributions = gates
        .iter()
        .map(|gate| ProductNodeContribution::new(gate.holds.clone(), gate.holds_cross))
        .collect::<Vec<_>>();
    let mut bit_transcript = Transcript::new(b"qomm:quote:gate:bit");
    bit_transcript.append_message(b"ctx", &context);
    let (bit_proof, bit_record) = joint_prove_product_from_contributions(
        &circuit.key,
        &first.holds.commitment(),
        &first.holds.commitment(),
        &bit_contributions,
        quorum,
        threshold,
        &mut bit_transcript,
        &mut *rng,
    )?;
    products.push((
        format!("maker {maker_index} {} bit", String::from_utf8_lossy(name)),
        bit_record,
    ));

    let product_contributions = gates
        .iter()
        .map(|gate| ProductNodeContribution::new(gate.value.clone(), gate.product_cross))
        .collect::<Vec<_>>();
    let mut product_transcript = Transcript::new(b"qomm:quote:gate:prod");
    product_transcript.append_message(b"ctx", &context);
    let (product_proof, product_record) = joint_prove_product_from_contributions(
        &circuit.key,
        &first.holds.commitment(),
        &first.product.commitment(),
        &product_contributions,
        quorum,
        threshold,
        &mut product_transcript,
        &mut *rng,
    )?;
    products.push((
        format!(
            "maker {maker_index} {} product",
            String::from_utf8_lossy(name)
        ),
        product_record,
    ));
    let range_contributions = gates
        .iter()
        .map(|gate| gate.bits.clone())
        .collect::<Vec<_>>();
    let range_context = QuoteCircuit::gate_range_context(proof_context, maker_index, name);
    let (range, range_record) = joint_prove_range_from_contributions(
        &circuit.key,
        &range_contributions,
        quorum,
        &range_context,
        &mut *rng,
    )?;
    ranges.push((
        format!(
            "maker {maker_index} {} range",
            String::from_utf8_lossy(name)
        ),
        range_record,
    ));
    Ok((
        Gate {
            commitment: first.holds.commitment(),
            bit_proof: BitValidityProof::Square(bit_proof),
            product: product_proof,
            product_commitment: first.product.commitment(),
            witness_commitment: first.witness.commitment(),
        },
        range,
    ))
}

/// Assemble a quote from independent recipient-scoped node contributions.
/// The assembler never accepts `ScalarShares` or any aggregate private object.
pub fn joint_prove_quote<R: RngCore + CryptoRng>(
    circuit: &QuoteCircuit,
    contributions: &[QuoteNodeContribution],
    public: &Public,
    quorum: &[PartyId],
    context: &[u8],
    rng: &mut R,
) -> Result<(QuoteProof, QuoteAssemblyTranscript), String> {
    let nodes = quote_quorum(contributions, quorum)?;
    let first = nodes[0];
    if first.makers.len() != public.registry.len() {
        return Err(
            "the node contributions and public registry have different maker counts".into(),
        );
    }
    if first.qty.commitment().compress() != public.qty_commitment.compress() {
        return Err("the node contributions are for a different quantity commitment".into());
    }
    let proof_context = QuoteCircuit::statement_context(context, public);
    let mut maker_proofs = Vec::with_capacity(first.makers.len());
    let mut product_partials = Vec::new();
    let mut range_partials = Vec::new();

    for index in 0..first.makers.len() {
        let maker = &first.makers[index];
        let depth_contributions = nodes
            .iter()
            .map(|node| {
                ProductNodeContribution::new(node.qty.clone(), node.makers[index].depth_cross)
            })
            .collect::<Vec<_>>();
        let (depth, depth_record) = joint_prove_product_from_contributions(
            &circuit.key,
            &maker.fields.slope.commitment(),
            &maker.depth.commitment(),
            &depth_contributions,
            quorum,
            first.threshold,
            &mut QuoteCircuit::tag(&proof_context, index, "depth"),
            &mut *rng,
        )?;
        product_partials.push((format!("maker {index} depth"), depth_record));

        let skew_contributions = nodes
            .iter()
            .map(|node| {
                ProductNodeContribution::new(
                    node.makers[index].fields.inv.clone(),
                    node.makers[index].skew_cross,
                )
            })
            .collect::<Vec<_>>();
        let (skew, skew_record) = joint_prove_product_from_contributions(
            &circuit.key,
            &maker.fields.invcoef.commitment(),
            &maker.skew.commitment(),
            &skew_contributions,
            quorum,
            first.threshold,
            &mut QuoteCircuit::tag(&proof_context, index, "skew"),
            &mut *rng,
        )?;
        product_partials.push((format!("maker {index} skew"), skew_record));

        let fits = nodes
            .iter()
            .map(|node| &node.makers[index].fits)
            .collect::<Vec<_>>();
        let (fits_gate, fits_range) = joint_gate_from_contributions(
            circuit,
            &fits,
            quorum,
            first.threshold,
            &proof_context,
            index,
            b"fits",
            &mut *rng,
            &mut product_partials,
            &mut range_partials,
        )?;
        let fresh = nodes
            .iter()
            .map(|node| &node.makers[index].fresh)
            .collect::<Vec<_>>();
        let (fresh_gate, fresh_range) = joint_gate_from_contributions(
            circuit,
            &fresh,
            quorum,
            first.threshold,
            &proof_context,
            index,
            b"fresh",
            &mut *rng,
            &mut product_partials,
            &mut range_partials,
        )?;

        let active_contributions = nodes
            .iter()
            .map(|node| {
                ProductNodeContribution::new(
                    node.makers[index].fields.active.clone(),
                    node.makers[index].active_cross,
                )
            })
            .collect::<Vec<_>>();
        let (active_bit, active_record) = joint_prove_product_from_contributions(
            &circuit.key,
            &maker.fields.active.commitment(),
            &maker.fields.active.commitment(),
            &active_contributions,
            quorum,
            first.threshold,
            &mut QuoteCircuit::tag(&proof_context, index, "active"),
            &mut *rng,
        )?;
        product_partials.push((format!("maker {index} active bit"), active_record));

        let reference_contributions = nodes
            .iter()
            .map(|node| {
                ProductNodeContribution::new(
                    node.makers[index].fields.use_ref.clone(),
                    node.makers[index].reference_cross,
                )
            })
            .collect::<Vec<_>>();
        let (reference_bit, reference_record) = joint_prove_product_from_contributions(
            &circuit.key,
            &maker.fields.use_ref.commitment(),
            &maker.fields.use_ref.commitment(),
            &reference_contributions,
            quorum,
            first.threshold,
            &mut QuoteCircuit::tag(&proof_context, index, "reference"),
            &mut *rng,
        )?;
        product_partials.push((format!("maker {index} reference bit"), reference_record));

        let first_contributions = nodes
            .iter()
            .map(|node| {
                ProductNodeContribution::new(
                    node.makers[index].fresh.holds.clone(),
                    node.makers[index].both_cross,
                )
            })
            .collect::<Vec<_>>();
        let (first_product, first_record) = joint_prove_product_from_contributions(
            &circuit.key,
            &maker.fits.holds.commitment(),
            &maker.both.commitment(),
            &first_contributions,
            quorum,
            first.threshold,
            &mut QuoteCircuit::tag(&proof_context, index, "ok1"),
            &mut *rng,
        )?;
        product_partials.push((format!("maker {index} conjunction 1"), first_record));

        let second_contributions = nodes
            .iter()
            .map(|node| {
                let asset_match = Scalar::from(u64::from(
                    public.registry[index].maker_asset == public.asset,
                ));
                ProductNodeContribution::new(
                    node.makers[index].fields.active.scaled(&asset_match),
                    node.makers[index].ok_cross,
                )
            })
            .collect::<Vec<_>>();
        let (second_product, second_record) = joint_prove_product_from_contributions(
            &circuit.key,
            &maker.both.commitment(),
            &maker.ok.commitment(),
            &second_contributions,
            quorum,
            first.threshold,
            &mut QuoteCircuit::tag(&proof_context, index, "ok2"),
            &mut *rng,
        )?;
        product_partials.push((format!("maker {index} conjunction 2"), second_record));

        let gate_contributions = nodes
            .iter()
            .map(|node| {
                ProductNodeContribution::new(
                    node.makers[index].shifted_cost.clone(),
                    node.makers[index].gated_cross,
                )
            })
            .collect::<Vec<_>>();
        let (gate_cost, gate_record) = joint_prove_product_from_contributions(
            &circuit.key,
            &maker.ok.commitment(),
            &maker.gated.commitment(),
            &gate_contributions,
            quorum,
            first.threshold,
            &mut QuoteCircuit::tag(&proof_context, index, "gate"),
            &mut *rng,
        )?;
        product_partials.push((format!("maker {index} gated cost"), gate_record));

        maker_proofs.push(MakerProof {
            depth,
            skew,
            gate_cost,
            eligibility: EligibilityProof::Threshold {
                fits: Box::new(fits_range),
                fresh: Box::new(fresh_range),
            },
            active_bit: BitValidityProof::Square(active_bit),
            reference_bit: BitValidityProof::Square(reference_bit),
            fits_gate,
            fresh_gate,
            conjunction: (first_product, second_product),
            commitments: MakerCommitments {
                slope: maker.fields.slope.commitment(),
                invcoef: maker.fields.invcoef.commitment(),
                inv: maker.fields.inv.commitment(),
                depth: maker.depth.commitment(),
                skew: maker.skew.commitment(),
                fits: maker.fits.value.commitment(),
                fresh: maker
                    .fields
                    .expiry
                    .shifted(&circuit.key, &-scalar(public.now))
                    .commitment(),
                active: maker.fields.active.commitment(),
                ok: maker.ok.commitment(),
                fresh_strict: maker.fresh.value.commitment(),
                both: maker.both.commitment(),
                cost: maker.cost.commitment(),
                gated: maker.gated.commitment(),
                shifted_cost: maker.shifted_cost.commitment(),
            },
        });
    }

    let winner_contributions = nodes
        .iter()
        .map(|node| {
            let winner = node
                .key_wires
                .get(first.winner_index)
                .ok_or_else(|| "winner index is outside the shared key vector".to_string())?
                .shifted(&circuit.key, &-Scalar::from(first.winner_value));
            let (value, blinding) = winner.own_evaluation();
            Ok(OpeningNodeContribution::new(node.party, value, blinding))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let winner_commitment = first.key_wires[first.winner_index]
        .shifted(&circuit.key, &-Scalar::from(first.winner_value))
        .commitment();
    let (winner_opening, winner_partials) = joint_opening_from_contributions(
        &circuit.key,
        &winner_commitment,
        &winner_contributions,
        first.threshold,
        quorum,
        &mut QuoteCircuit::whole(&proof_context, "winner"),
        &mut *rng,
    )?;

    let mut minimality = Vec::with_capacity(first.minimality.len());
    for index in 0..first.minimality.len() {
        let range_contributions = nodes
            .iter()
            .map(|node| node.minimality[index].clone())
            .collect::<Vec<_>>();
        let range_context = QuoteCircuit::minimality_context(&proof_context, index);
        let (proof, record) = joint_prove_range_from_contributions(
            &circuit.key,
            &range_contributions,
            quorum,
            &range_context,
            &mut *rng,
        )?;
        minimality.push(proof);
        range_partials.push((format!("maker {index} minimality"), record));
    }
    Ok((
        QuoteProof {
            winner_index: first.winner_index,
            winner_value: first.winner_value,
            maker_proofs,
            winner_opening,
            minimality: MinimalityProof::Threshold(minimality),
            key_commitments: first.key_wires.iter().map(NodeShared::commitment).collect(),
        },
        QuoteAssemblyTranscript {
            quorum: quorum.to_vec(),
            product_partials,
            range_partials,
            winner_partials,
        },
    ))
}

// Circuit-wire metadata is checked here, but raw circuit shares are not a
// sufficient proof handoff: product cross terms, range bits, blindings and the
// public winner must be emitted by the MPC as recipient-scoped outputs.

/// Ristretto's scalar-field order, little endian, as recorded beside an MPC
/// wire export before those bytes are reduced to `Scalar` values.
pub const RISTRETTO_SCALAR_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Clone, Debug)]
pub struct CircuitWires {
    pub prime_le: [u8; 32],
    pub qty: ScalarShares,
    pub makers: Vec<BTreeMap<String, ScalarShares>>,
}

/// Refuse an MPC field whose shares are not witnesses in Ristretto's scalar
/// field. Metadata is checked before any commitment is derived.
pub fn check_circuit_field(wires: &CircuitWires) -> Result<(), String> {
    if wires.prime_le != RISTRETTO_SCALAR_ORDER_LE {
        let written_bits = wires
            .prime_le
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |index| {
                index * 8 + (u8::BITS - wires.prime_le[index].leading_zeros()) as usize
            });
        return Err(format!(
            "the circuit wrote in a field of {written_bits} bits and the commitments live in one of 253; run the circuit with --shamir-inputs so the two match"
        ));
    }
    Ok(())
}

/// Refuse an incomplete circuit handoff instead of reconstructing missing
/// auxiliary values in the assembler.
///
/// The MPC must emit recipient-scoped `QuoteNodeContribution` values containing all product
/// cross terms, range bits/blindings, and the public winner.  Raw wire maps do
/// not contain those outputs, so accepting them would require opening secrets.
#[allow(clippy::too_many_arguments)]
pub fn shares_from_circuit<R: RngCore + CryptoRng>(
    _circuit: &QuoteCircuit,
    wires: &CircuitWires,
    _quorum: &[PartyId],
    _parties: &[PartyId],
    _threshold: usize,
    _direction: u8,
    _now: i64,
    _sentinel: i64,
    _n_slots: i64,
    _rng: &mut R,
) -> Result<Vec<QuoteNodeContribution>, String> {
    check_circuit_field(wires)?;
    Err("circuit handoff omitted private MPC auxiliary outputs; refusing to reconstruct quantity, gates, active flags, costs, keys, or blindings in the proof assembler".into())
}

#[cfg(test)]
mod process_round_tests {
    use super::*;
    use rand_core::OsRng;

    fn local_wire(wire: &NodeShared, threshold: usize) -> LocalShared {
        let (value, blinding) = wire.own_evaluation();
        LocalShared::new(wire.party(), value, blinding, threshold).unwrap()
    }

    fn local_range(range: &NodeValueShares, threshold: usize) -> LocalRangeShares {
        let (value, blinding) = range.own_evaluation();
        LocalRangeShares::new(
            range.party(),
            value,
            blinding,
            range.bit_evaluations(),
            threshold,
        )
        .unwrap()
    }

    fn local_node(node: &QuoteNodeContribution) -> LocalQuoteNode {
        let makers = node
            .makers
            .iter()
            .zip(&node.minimality)
            .map(|(maker, minimum)| LocalQuoteMakerInput {
                fields: LocalQuotePolicyInput {
                    ask_level: local_wire(&maker.fields.ask_level, node.threshold),
                    spread: local_wire(&maker.fields.spread, node.threshold),
                    slope: local_wire(&maker.fields.slope, node.threshold),
                    invcoef: local_wire(&maker.fields.invcoef, node.threshold),
                    inv: local_wire(&maker.fields.inv, node.threshold),
                    maxqty: local_wire(&maker.fields.maxqty, node.threshold),
                    expiry: local_wire(&maker.fields.expiry, node.threshold),
                    active: local_wire(&maker.fields.active, node.threshold),
                    use_ref: local_wire(&maker.fields.use_ref, node.threshold),
                },
                depth: local_wire(&maker.depth, node.threshold),
                depth_cross: maker.depth_cross,
                skew: local_wire(&maker.skew, node.threshold),
                skew_cross: maker.skew_cross,
                fits: LocalQuoteGateInput {
                    value: local_wire(&maker.fits.value, node.threshold),
                    holds: local_wire(&maker.fits.holds, node.threshold),
                    holds_cross: maker.fits.holds_cross,
                    product: local_wire(&maker.fits.product, node.threshold),
                    product_cross: maker.fits.product_cross,
                    witness: local_range(&maker.fits.bits, node.threshold),
                },
                fresh: LocalQuoteGateInput {
                    value: local_wire(&maker.fresh.value, node.threshold),
                    holds: local_wire(&maker.fresh.holds, node.threshold),
                    holds_cross: maker.fresh.holds_cross,
                    product: local_wire(&maker.fresh.product, node.threshold),
                    product_cross: maker.fresh.product_cross,
                    witness: local_range(&maker.fresh.bits, node.threshold),
                },
                active_cross: maker.active_cross,
                reference_cross: maker.reference_cross,
                both: local_wire(&maker.both, node.threshold),
                both_cross: maker.both_cross,
                ok: local_wire(&maker.ok, node.threshold),
                ok_cross: maker.ok_cross,
                gated: local_wire(&maker.gated, node.threshold),
                gated_cross: maker.gated_cross,
                cost: local_wire(&maker.cost, node.threshold),
                packed: local_wire(&maker.packed, node.threshold),
                minimality: local_range(minimum, node.threshold),
            })
            .collect();
        LocalQuoteNode::new(
            local_wire(&node.qty, node.threshold),
            makers,
            node.parties.clone(),
            node.threshold,
        )
        .unwrap()
    }

    #[test]
    fn process_isolated_rounds_produce_the_ordinary_quote_proof() {
        let circuit = QuoteCircuit::new(8, 12);
        let parties = vec![1, 2, 3, 4, 5, 6, 7];
        let threshold = 2;
        let makers = (0..2)
            .map(|index| MakerWitness {
                ask_level: 10_000 + index * 5,
                spread: 20,
                slope: 1 + index,
                invcoef: 1,
                inv: 3,
                maxqty: 500,
                expiry: 2_000,
                active: true,
                blindings: Registered::fresh(&mut OsRng),
            })
            .collect::<Vec<_>>();
        let (dealt, public) = deal_quote_shares(
            &circuit,
            &makers,
            100,
            0,
            1_000,
            1 << 20,
            8,
            &parties,
            threshold,
            [7; 32],
            42,
            &mut OsRng,
        )
        .unwrap();
        let local = dealt.iter().map(local_node).collect::<Vec<_>>();
        let evaluations = local
            .iter()
            .map(|node| node.evaluations(&circuit.key))
            .collect::<Vec<_>>();
        let statement = quote_statement_from_evaluations(
            &circuit,
            &evaluations,
            &public,
            dealt[0].winner_index,
            dealt[0].winner_value,
            &parties,
            threshold,
        )
        .unwrap();
        let bound = local
            .into_iter()
            .map(|node| node.bind(&circuit.key, &statement))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let relation_evaluations = bound
            .iter()
            .map(|node| node.relation_evaluations(&circuit, &public))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let relations = quote_relation_statements_from_evaluations(
            &circuit,
            &statement,
            &public,
            &relation_evaluations,
        )
        .unwrap();
        let quorum = vec![1, 3, 6];
        let selected = quorum
            .iter()
            .map(|party| &bound[party - 1])
            .collect::<Vec<_>>();
        let prepared = selected
            .iter()
            .map(|node| {
                node.prepare_round1(&circuit, &public, b"process-isolated-quote", &mut OsRng)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let seals = prepared
            .iter()
            .map(|(seal, _, _)| seal.clone())
            .collect::<Vec<_>>();
        let rounds = prepared
            .iter()
            .map(|(_, _, round)| round.clone())
            .collect::<Vec<_>>();
        let challenges = make_quote_challenges(
            &circuit,
            &statement,
            &relations,
            &public,
            QuoteChallengeTranscript {
                rounds: &rounds,
                seals: &seals,
                quorum: &quorum,
                context: b"process-isolated-quote",
            },
        )
        .unwrap();
        let responses = selected
            .into_iter()
            .zip(prepared.into_iter().map(|(_, secret, _)| secret))
            .map(|(node, secret)| node.answer_round1(&circuit, &public, secret, &challenges))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let proof = assemble_quote_from_rounds(
            &circuit,
            &statement,
            &relations,
            &public,
            &rounds,
            &seals,
            &responses,
            &quorum,
            b"process-isolated-quote",
        )
        .unwrap();
        assert_eq!(
            circuit.verify(&proof, &public, b"process-isolated-quote"),
            Ok(())
        );
    }
}
