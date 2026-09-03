//! Convert one node's complete MP-SPDZ quote handoff into a local proof node.
//!
//! This module deliberately has no API accepting more than one persistence
//! file.  Public Pedersen evaluations are the only values exchanged between
//! proof processes; scalar shares stay in the process that read them.

use curve25519_dalek::scalar::Scalar;
use qomm_mpc::persistence::{FieldElement, LocalQuoteMakerHandoff, LocalQuoteProofHandoff};
use qomm_proofs::threshold_gadgets::LocalShared;
use qomm_proofs::threshold_quote::{
    LocalQuoteGateInput, LocalQuoteMakerInput, LocalQuoteNode, LocalQuotePolicyInput,
    RISTRETTO_SCALAR_ORDER_LE,
};
use qomm_proofs::threshold_sigma::PartyId;

use crate::zkpi_issuer::{field_scalar, local_range};

fn named<'a>(
    values: &'a std::collections::BTreeMap<&'static str, FieldElement>,
    name: &str,
) -> Result<&'a FieldElement, String> {
    values
        .get(name)
        .ok_or_else(|| format!("quote handoff omitted {name}"))
}

fn local_wire(
    party: PartyId,
    value: &FieldElement,
    blinding: &FieldElement,
    threshold: usize,
) -> Result<LocalShared, String> {
    LocalShared::new(
        party,
        field_scalar(value)?,
        field_scalar(blinding)?,
        threshold,
    )
}

fn maker(
    party: PartyId,
    handoff: LocalQuoteMakerHandoff,
    qty_blinding: Scalar,
    threshold: usize,
) -> Result<LocalQuoteMakerInput, String> {
    let core = |name: &str| named(&handoff.core_wire_shares, name);
    let policy_blinding = |name: &str| named(&handoff.policy_blinding_shares, name);
    let derived_blinding = |name: &str| named(&handoff.derived_blinding_shares, name);
    let cross = |name: &str| -> Result<Scalar, String> {
        field_scalar(named(&handoff.cross_shares, name)?)
    };
    let fields = LocalQuotePolicyInput {
        ask_level: local_wire(
            party,
            core("ask_level")?,
            policy_blinding("ask_level")?,
            threshold,
        )?,
        spread: local_wire(
            party,
            core("spread")?,
            policy_blinding("spread")?,
            threshold,
        )?,
        slope: local_wire(party, core("slope")?, policy_blinding("slope")?, threshold)?,
        invcoef: local_wire(
            party,
            core("invcoef")?,
            policy_blinding("invcoef")?,
            threshold,
        )?,
        inv: local_wire(party, core("inv")?, policy_blinding("inv")?, threshold)?,
        maxqty: local_wire(
            party,
            core("maxqty")?,
            policy_blinding("maxqty")?,
            threshold,
        )?,
        expiry: local_wire(
            party,
            core("expiry")?,
            policy_blinding("expiry")?,
            threshold,
        )?,
        active: local_wire(
            party,
            core("active")?,
            policy_blinding("active")?,
            threshold,
        )?,
        use_ref: local_wire(
            party,
            &handoff.use_ref_share,
            policy_blinding("use_ref")?,
            threshold,
        )?,
    };
    let maxqty_blinding = field_scalar(policy_blinding("maxqty")?)?;
    let expiry_blinding = field_scalar(policy_blinding("expiry")?)?;
    let fits = LocalQuoteGateInput {
        value: LocalShared::new(
            party,
            field_scalar(core("fits_margin")?)?,
            maxqty_blinding - qty_blinding,
            threshold,
        )?,
        holds: local_wire(
            party,
            core("fits")?,
            derived_blinding("fits_bit")?,
            threshold,
        )?,
        holds_cross: cross("fits_bit")?,
        product: local_wire(
            party,
            core("fits_product")?,
            derived_blinding("fits_product")?,
            threshold,
        )?,
        product_cross: cross("fits_product")?,
        witness: local_range(party, handoff.fits_witness, threshold)?,
    };
    let fresh = LocalQuoteGateInput {
        value: LocalShared::new(
            party,
            field_scalar(core("fresh_margin")?)?,
            expiry_blinding,
            threshold,
        )?,
        holds: local_wire(
            party,
            core("fresh_bit")?,
            derived_blinding("fresh_bit")?,
            threshold,
        )?,
        holds_cross: cross("fresh_bit")?,
        product: local_wire(
            party,
            core("fresh_product")?,
            derived_blinding("fresh_product")?,
            threshold,
        )?,
        product_cross: cross("fresh_product")?,
        witness: local_range(party, handoff.fresh_witness, threshold)?,
    };
    Ok(LocalQuoteMakerInput {
        fields,
        depth: local_wire(party, core("depth")?, derived_blinding("depth")?, threshold)?,
        depth_cross: cross("depth")?,
        skew: local_wire(party, core("skew")?, derived_blinding("skew")?, threshold)?,
        skew_cross: cross("skew")?,
        fits,
        fresh,
        active_cross: cross("active")?,
        reference_cross: cross("reference")?,
        both: local_wire(party, core("both")?, derived_blinding("both")?, threshold)?,
        both_cross: cross("both")?,
        ok: local_wire(party, core("ok")?, derived_blinding("ok")?, threshold)?,
        ok_cross: cross("ok")?,
        gated: local_wire(party, core("gated")?, derived_blinding("gated")?, threshold)?,
        gated_cross: cross("gated")?,
        cost: local_wire(party, core("cost")?, derived_blinding("cost")?, threshold)?,
        packed: LocalShared::new(
            party,
            field_scalar(core("key")?)?,
            field_scalar(&handoff.key_blinding_share)?,
            threshold,
        )?,
        minimality: local_range(party, handoff.minimality, threshold)?,
    })
}

pub struct MpcQuoteNode {
    inner: LocalQuoteNode,
}

impl MpcQuoteNode {
    /// MP-SPDZ persistence paths are zero-indexed; Shamir evaluation points in
    /// the proof protocol are one-indexed.
    pub fn from_handoff(
        handoff: LocalQuoteProofHandoff,
        parties: Vec<PartyId>,
        threshold: usize,
    ) -> Result<Self, String> {
        let prime: [u8; 32] = handoff
            .prime
            .to_bytes_le(32)
            .map_err(|error| error.to_string())?
            .try_into()
            .expect("a requested 32-byte encoding");
        if prime != RISTRETTO_SCALAR_ORDER_LE {
            return Err("MPC and quote commitments use different scalar fields".into());
        }
        let party = handoff
            .party
            .checked_add(1)
            .ok_or("MPC party identifier overflow")?;
        let qty_blinding = field_scalar(&handoff.qty_blinding_share)?;
        let qty = LocalShared::new(
            party,
            field_scalar(&handoff.qty_share)?,
            qty_blinding,
            threshold,
        )?;
        let makers = handoff
            .makers
            .into_iter()
            .map(|handoff| maker(party, handoff, qty_blinding, threshold))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            inner: LocalQuoteNode::new(qty, makers, parties, threshold)?,
        })
    }

    pub fn party(&self) -> PartyId {
        self.inner.party()
    }

    pub fn into_inner(self) -> LocalQuoteNode {
        self.inner
    }

    pub fn inner(&self) -> &LocalQuoteNode {
        &self.inner
    }
}
