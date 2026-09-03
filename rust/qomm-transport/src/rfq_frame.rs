//! Typed construction of the fixed-width resident-MPC RFQ frame.
//!
//! The transport wire deliberately contains no public RFQ metadata.  This
//! module is the admission boundary that proves the secret values being shared
//! are the openings already signed by the Taker.  Maker reserve shares are not
//! accepted here: they remain standing, encrypted node-local MPC state.

use crate::mandate::{Direction, TakerExecutionMandate};
use crate::mpc_result::fill_mask_scalar_commitment;
use crate::wire::{share_field_elements, FieldElement, WireError, PAYLOAD_BYTES};
use curve25519_dalek::scalar::Scalar;
use qomm_zk::Pedersen;
use rand_core::{CryptoRng, RngCore};

pub const RESIDENT_RFQ_FIELDS: usize = 14;
const COMMITMENT_DOMAIN: &[u8] = b"qomm:defmi:v1";

#[derive(Clone, Debug)]
pub struct ResidentRfqCatalogBinding {
    pub asset_index: u64,
    pub asset_count: u64,
    pub traded_asset_id: [u8; 32],
    pub cash_asset_id: [u8; 32],
    /// Secret venue-local legal-entity pseudonym. It is never placed on the
    /// public wire and must be non-zero so it cannot be confused with cover.
    pub entity_slot: u64,
}

#[derive(Clone, Debug)]
pub struct ResidentRfqOpenings {
    pub quantity: u64,
    pub quantity_blinding: Scalar,
    pub executable_limit: u64,
    pub limit_blinding: Scalar,
    /// The one direction-relevant DeFMI reserve. For a buy this is cash; for a
    /// sell it is the traded security. The unused rail is shared as zero.
    pub reserve_amount: u64,
    pub reserve_blinding: Scalar,
    /// One-time masks retained only by the Taker. Every cover frame receives
    /// independently random masks as well, so an MPC node cannot recognize a
    /// cover lane from its opened response.
    pub response_mask: Scalar,
    pub fill_mask: Scalar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidentRfqInput {
    values: [FieldElement; RESIDENT_RFQ_FIELDS],
}

impl ResidentRfqInput {
    pub fn from_signed_mandate(
        mandate: &TakerExecutionMandate,
        catalog: &ResidentRfqCatalogBinding,
        openings: &ResidentRfqOpenings,
        slot: u32,
        now: u64,
    ) -> Result<Self, String> {
        mandate.verify_signature_at(now)?;
        if mandate.admission_slot != u64::from(slot) {
            return Err("Taker mandate belongs to another admission slot".into());
        }
        if mandate.allow_partial {
            return Err("resident RFQ circuit does not yet accept partial-fill mandates".into());
        }
        if catalog.asset_count == 0 || catalog.asset_index >= catalog.asset_count {
            return Err("RFQ asset index is outside the approved private catalog".into());
        }
        if catalog.entity_slot == 0 {
            return Err("RFQ legal-entity pseudonym must be non-zero".into());
        }
        if mandate.asset_id != catalog.traded_asset_id {
            return Err("Taker mandate names another traded asset".into());
        }
        let expected_reserve_asset = match mandate.direction {
            Direction::TakerBuys => catalog.cash_asset_id,
            Direction::TakerSells => catalog.traded_asset_id,
        };
        if mandate.reserve_asset_id != expected_reserve_asset {
            return Err("Taker mandate reserves the wrong settlement rail".into());
        }
        if openings.quantity == 0 || openings.reserve_amount == 0 {
            return Err("Taker quantity and reserve must be positive".into());
        }
        if mandate.direction == Direction::TakerSells && openings.reserve_amount < openings.quantity
        {
            return Err("Taker securities reserve is smaller than the signed quantity".into());
        }
        if openings.quantity_blinding == Scalar::ZERO
            || openings.limit_blinding == Scalar::ZERO
            || openings.reserve_blinding == Scalar::ZERO
            || openings.response_mask == Scalar::ZERO
            || openings.fill_mask == Scalar::ZERO
        {
            return Err("RFQ openings and one-time response masks must be non-zero".into());
        }

        let key = Pedersen::new(COMMITMENT_DOMAIN);
        let committed =
            |value: u64, blinding: &Scalar| key.commit_u64(value, blinding).compress().to_bytes();
        if committed(openings.quantity, &openings.quantity_blinding) != mandate.quantity_commitment
            || committed(openings.executable_limit, &openings.limit_blinding)
                != mandate.limit_price_commitment
            || committed(openings.reserve_amount, &openings.reserve_blinding)
                != mandate.maximum_amount_commitment
            || fill_mask_scalar_commitment(openings.fill_mask.to_bytes())
                != mandate.fill_mask_commitment
        {
            return Err("RFQ openings do not match the signed Taker mandate".into());
        }

        let direction = match mandate.direction {
            Direction::TakerBuys => 0,
            Direction::TakerSells => 1,
        };
        let zero = FieldElement::ZERO;
        let (securities_amount, securities_blinding, cash_amount, cash_blinding) =
            match mandate.direction {
                Direction::TakerBuys => (
                    zero,
                    zero,
                    FieldElement::from_u64(openings.reserve_amount),
                    scalar_field(openings.reserve_blinding),
                ),
                Direction::TakerSells => (
                    FieldElement::from_u64(openings.reserve_amount),
                    scalar_field(openings.reserve_blinding),
                    zero,
                    zero,
                ),
            };
        Ok(Self {
            values: [
                FieldElement::from_u64(catalog.asset_index),
                FieldElement::from_u64(openings.quantity),
                FieldElement::from_u64(direction),
                FieldElement::from_u64(catalog.entity_slot),
                FieldElement::from_u64(1),
                scalar_field(openings.response_mask),
                FieldElement::from_u64(openings.executable_limit),
                scalar_field(openings.limit_blinding),
                scalar_field(openings.fill_mask),
                scalar_field(openings.quantity_blinding),
                securities_amount,
                securities_blinding,
                cash_amount,
                cash_blinding,
            ],
        })
    }

    /// Build an indistinguishable no-query lane. The secret real/cover bit is
    /// zero, while response masks remain random so opened MPC output is not an
    /// unmasked market quote on cover traffic.
    pub fn cover(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let response_mask = nonzero_scalar(rng);
        let fill_mask = nonzero_scalar(rng);
        let mut values = [FieldElement::ZERO; RESIDENT_RFQ_FIELDS];
        values[5] = scalar_field(response_mask);
        values[8] = scalar_field(fill_mask);
        Self { values }
    }

    pub fn values(&self) -> &[FieldElement; RESIDENT_RFQ_FIELDS] {
        &self.values
    }

    pub fn share(&self, n_nodes: usize) -> Result<Vec<[u8; PAYLOAD_BYTES]>, WireError> {
        share_field_elements(&self.values, n_nodes)
    }
}

fn nonzero_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Scalar {
    loop {
        let value = Scalar::random(rng);
        if value != Scalar::ZERO {
            return value;
        }
    }
}

fn scalar_field(value: Scalar) -> FieldElement {
    let mut bytes = value.to_bytes();
    bytes.reverse();
    FieldElement::from_be_bytes(bytes).expect("a canonical Scalar is a wire field element")
}
