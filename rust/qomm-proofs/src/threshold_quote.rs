//! Whole quote proofs assembled by a quorum that holds only Shamir shares.
//!
//! `deal_quote_shares` models the output shape of the MPC: every multiplication
//! output has been degree-reduced, every bit decomposition has been shared, and
//! the public winner is available. `joint_prove_quote` accepts that handoff and
//! the public statement, never a [`MakerWitness`]. It emits the same
//! [`QuoteProof`] accepted by [`QuoteCircuit::verify`].

use std::collections::BTreeMap;

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
    add, joint_prove_product_from_contributions, negate, scale, shift, sub, NodeShared,
    ProductAssemblyTranscript, ProductNodeContribution, Shared,
};
use crate::threshold_range::{
    bits_for, joint_prove_range_from_contributions, NodeValueShares, RangeAssemblyTranscript,
    ThresholdRangeProof, ValueShares,
};
use crate::threshold_sigma::{
    deal, joint_opening_from_contributions, share_scalar, OpeningAssemblyTranscript,
    OpeningNodeContribution, PartyId, ScalarShares,
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
}

impl DealerPolicyShares {
    #[cfg(any())]
    fn wires(&self) -> [&Shared; 8] {
        [
            &self.ask_level,
            &self.spread,
            &self.slope,
            &self.invcoef,
            &self.inv,
            &self.maxqty,
            &self.expiry,
            &self.active,
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
            &self.fits.holds,
            &self.fits.product,
            &self.fits.witness,
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
}

impl NodePolicyShares {
    fn wires(&self) -> [&NodeShared; 8] {
        [
            &self.ask_level,
            &self.spread,
            &self.slope,
            &self.invcoef,
            &self.inv,
            &self.maxqty,
            &self.expiry,
            &self.active,
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
            &self.fits.holds,
            &self.fits.product,
            &self.fits.witness,
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
    let qty_blinding = dealer.random_scalar();
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
        let packed_value = checked_add(
            checked_mul(effective, n_slots, "packed key overflow")?,
            i64::try_from(index).map_err(|_| "maker index does not fit i64")?,
            "packed key overflow",
        )?;
        if packed_value < 0 {
            return Err("a packed key went negative; widen the sentinel".into());
        }
        let packed = shift(
            key,
            &scale(&gated, &scalar(n_slots)),
            &scalar(checked_add(
                checked_mul(sentinel, n_slots, "packed key overflow")?,
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
                ProductNodeContribution::new(
                    node.makers[index].fields.active.clone(),
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
