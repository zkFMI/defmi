//! Pre-trade authority for settlement without a post-quote signature.
//!
//! A Maker signs a price-policy version together with its DeFMI reservation.
//! A Taker signs an RFQ together with its maximum liability and reservation.
//! Neither signature contains the eventual exact price.  The MPC quorum may
//! settle only when its result satisfies both signed envelopes.

use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qomm_proofs::kyb::{verify_presentation, KybPresentation, SignedCohortRegistry};
use sha2::{Digest, Sha256};

const MAKER_DOMAIN: &[u8] = b"QOMM:MAKER:POLICY-MANDATE:v1";
const TAKER_DOMAIN: &[u8] = b"QOMM:TAKER:EXECUTION-MANDATE:v1";
pub const ZERO: [u8; 32] = [0; 32];

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn nonzero(values: &[&[u8; 32]]) -> bool {
    values.iter().all(|value| **value != ZERO)
}

fn valid_handle(value: &[u8; 32]) -> bool {
    CompressedRistretto(*value).decompress().is_some()
}

struct MandateReader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> MandateReader<'a> {
    fn new(bytes: &'a [u8], domain: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(domain) {
            return Err("mandate has the wrong domain".into());
        }
        Ok(Self {
            bytes,
            at: domain.len(),
        })
    }

    fn take<const N: usize>(&mut self, name: &str) -> Result<[u8; N], String> {
        let end = self
            .at
            .checked_add(N)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| format!("mandate is truncated at {name}"))?;
        let value = self.bytes[self.at..end]
            .try_into()
            .map_err(|_| format!("mandate is truncated at {name}"))?;
        self.at = end;
        Ok(value)
    }

    fn u64(&mut self, name: &str) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.take(name)?))
    }

    fn boolean(&mut self, name: &str) -> Result<bool, String> {
        match self.take::<1>(name)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(format!("mandate {name} is not canonical")),
        }
    }

    fn direction(&mut self) -> Result<Direction, String> {
        match self.take::<1>("direction")?[0] {
            1 => Ok(Direction::TakerBuys),
            2 => Ok(Direction::TakerSells),
            _ => Err("mandate direction is invalid".into()),
        }
    }

    fn finish(self) -> Result<(), String> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err("mandate has trailing bytes".into())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    TakerBuys = 1,
    TakerSells = 2,
}

#[derive(Clone, Debug)]
pub struct MakerPolicyMandate {
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub policy_digest: [u8; 32],
    pub policy_version: u64,
    pub asset_id: [u8; 32],
    pub direction: Direction,
    pub reserve_id: [u8; 32],
    pub maximum_amount_commitment: [u8; 32],
    pub maker_handle: [u8; 32],
    pub entity_commitment: [u8; 32],
    pub kyb_presentation_digest: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub auto_execute: bool,
    pub maker_public: [u8; 32],
    pub signature: Signature,
}

impl MakerPolicyMandate {
    /// Decode the exact signed body used on the wire between a coordinator and
    /// an isolated threshold signer.  The method round-trips the canonical
    /// encoder and verifies the Maker signature; it does not replace the KYB
    /// presentation check performed by the intake and DeFMI services.
    pub fn from_signed_bytes(unsigned: &[u8], signature: [u8; 64]) -> Result<Self, String> {
        let mut reader = MandateReader::new(unsigned, MAKER_DOMAIN)?;
        let value = Self {
            venue_id: reader.take("venue")?,
            defmi_id: reader.take("DeFMI")?,
            policy_digest: reader.take("policy")?,
            policy_version: reader.u64("policy version")?,
            asset_id: reader.take("asset")?,
            direction: reader.direction()?,
            reserve_id: reader.take("reserve")?,
            maximum_amount_commitment: reader.take("maximum amount")?,
            maker_handle: reader.take("Maker handle")?,
            entity_commitment: reader.take("entity")?,
            kyb_presentation_digest: reader.take("KYB presentation")?,
            valid_from: reader.u64("valid from")?,
            valid_until: reader.u64("valid until")?,
            auto_execute: reader.boolean("auto execute")?,
            maker_public: reader.take("Maker public key")?,
            signature: Signature::from_bytes(&signature),
        };
        reader.finish()?;
        if value.unsigned()? != unsigned {
            return Err("Maker mandate is not canonically encoded".into());
        }
        value.verify_signature()?;
        Ok(value)
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        VerifyingKey::from_bytes(&self.maker_public)
            .map_err(|_| "Maker public key is malformed".to_string())?
            .verify(&self.unsigned()?, &self.signature)
            .map_err(|_| "Maker policy mandate signature is invalid".to_string())
    }

    pub fn verify_signature_at(&self, now: u64) -> Result<(), String> {
        if now < self.valid_from || now > self.valid_until {
            return Err("Maker policy mandate is not currently valid".into());
        }
        self.verify_signature()
    }

    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if self.policy_version == 0
            || self.valid_from == 0
            || self.valid_until < self.valid_from
            || !self.auto_execute
            || !valid_handle(&self.maker_handle)
            || !nonzero(&[
                &self.venue_id,
                &self.defmi_id,
                &self.policy_digest,
                &self.asset_id,
                &self.reserve_id,
                &self.maximum_amount_commitment,
                &self.entity_commitment,
                &self.kyb_presentation_digest,
                &self.maker_public,
            ])
        {
            return Err("Maker policy mandate is incomplete or cannot auto-execute".into());
        }
        let mut body = MAKER_DOMAIN.to_vec();
        for value in [&self.venue_id, &self.defmi_id, &self.policy_digest] {
            body.extend_from_slice(value);
        }
        body.extend_from_slice(&self.policy_version.to_be_bytes());
        body.extend_from_slice(&self.asset_id);
        body.push(self.direction as u8);
        for value in [
            &self.reserve_id,
            &self.maximum_amount_commitment,
            &self.maker_handle,
            &self.entity_commitment,
            &self.kyb_presentation_digest,
        ] {
            body.extend_from_slice(value);
        }
        body.extend_from_slice(&self.valid_from.to_be_bytes());
        body.extend_from_slice(&self.valid_until.to_be_bytes());
        body.push(u8::from(self.auto_execute));
        body.extend_from_slice(&self.maker_public);
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(self.unsigned()?)
            .chain_update(self.signature.to_bytes())
            .finalize()
            .into())
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self, String> {
        if self.maker_public != key.verifying_key().to_bytes() {
            return Err("Maker signing key does not match the mandate".into());
        }
        self.signature = key.sign(&self.unsigned()?);
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        presentation: &KybPresentation,
        registry: &SignedCohortRegistry,
        trusted_issuer: &VerifyingKey,
        kyb_scope: &[u8],
        kyb_context: &[u8],
        required_cohort: &str,
        now: u64,
    ) -> Result<(), String> {
        if now < self.valid_from || now > self.valid_until {
            return Err("Maker policy mandate is not currently valid".into());
        }
        verify_presentation(
            presentation,
            registry,
            trusted_issuer,
            kyb_scope,
            kyb_context,
            now,
            required_cohort,
        )
        .map_err(|error| format!("Maker KYB presentation failed: {error:?}"))?;
        if self.kyb_presentation_digest != presentation.digest()
            || self.entity_commitment != presentation.entity_commitment()
        {
            return Err("Maker mandate is bound to another legal entity proof".into());
        }
        VerifyingKey::from_bytes(&self.maker_public)
            .map_err(|_| "Maker public key is malformed".to_string())?
            .verify(&self.unsigned()?, &self.signature)
            .map_err(|_| "Maker policy mandate signature is invalid".to_string())
    }
}

#[derive(Clone, Debug)]
pub struct TakerExecutionMandate {
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub rfq_nullifier: [u8; 32],
    pub asset_id: [u8; 32],
    /// Asset actually placed under DeFMI control before the RFQ is evaluated.
    /// This is cash for a buy and the traded asset for a sell; it is signed
    /// separately because `asset_id` always identifies the requested product.
    pub reserve_asset_id: [u8; 32],
    pub direction: Direction,
    pub quantity_commitment: [u8; 32],
    pub limit_price_commitment: [u8; 32],
    pub maximum_fee_commitment: [u8; 32],
    /// Maximum cash liability when buying, or the committed deliverable
    /// quantity when selling.  DeFMI binds the pre-trade reserve to this exact
    /// commitment, so the eventual quote can consume less but never more.
    pub maximum_amount_commitment: [u8; 32],
    pub reserve_id: [u8; 32],
    pub taker_handle: [u8; 32],
    pub entity_commitment: [u8; 32],
    pub kyb_presentation_digest: [u8; 32],
    /// Pre-issued admission ticket signed by the Taker before the opaque RFQ
    /// frame is submitted. The later ordering receipt deliberately is not part
    /// of this mandate; including it would be a circular signature dependency.
    pub admission_ticket_id: [u8; 32],
    pub admission_slot: u64,
    pub deadline: u64,
    pub allow_partial: bool,
    pub auto_settle: bool,
    pub taker_public: [u8; 32],
    pub signature: Signature,
}

impl TakerExecutionMandate {
    /// Decode and authenticate the exact pre-RFQ Taker mandate presented to an
    /// isolated threshold signer.
    pub fn from_signed_bytes(unsigned: &[u8], signature: [u8; 64]) -> Result<Self, String> {
        let mut reader = MandateReader::new(unsigned, TAKER_DOMAIN)?;
        let value = Self {
            venue_id: reader.take("venue")?,
            defmi_id: reader.take("DeFMI")?,
            rfq_nullifier: reader.take("RFQ nullifier")?,
            asset_id: reader.take("traded asset")?,
            reserve_asset_id: reader.take("reserve asset")?,
            direction: reader.direction()?,
            quantity_commitment: reader.take("quantity")?,
            limit_price_commitment: reader.take("limit price")?,
            maximum_fee_commitment: reader.take("maximum fee")?,
            maximum_amount_commitment: reader.take("maximum amount")?,
            reserve_id: reader.take("reserve")?,
            taker_handle: reader.take("Taker handle")?,
            entity_commitment: reader.take("entity")?,
            kyb_presentation_digest: reader.take("KYB presentation")?,
            admission_ticket_id: reader.take("admission ticket")?,
            admission_slot: reader.u64("admission slot")?,
            deadline: reader.u64("deadline")?,
            allow_partial: reader.boolean("allow partial")?,
            auto_settle: reader.boolean("auto settle")?,
            taker_public: reader.take("Taker public key")?,
            signature: Signature::from_bytes(&signature),
        };
        reader.finish()?;
        if value.unsigned()? != unsigned {
            return Err("Taker mandate is not canonically encoded".into());
        }
        value.verify_signature()?;
        Ok(value)
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        VerifyingKey::from_bytes(&self.taker_public)
            .map_err(|_| "Taker public key is malformed".to_string())?
            .verify(&self.unsigned()?, &self.signature)
            .map_err(|_| "Taker execution mandate signature is invalid".to_string())
    }

    pub fn verify_signature_at(&self, now: u64) -> Result<(), String> {
        if now > self.deadline {
            return Err("Taker execution mandate has expired".into());
        }
        self.verify_signature()
    }

    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if self.deadline == 0
            || !self.auto_settle
            || !valid_handle(&self.taker_handle)
            || !nonzero(&[
                &self.venue_id,
                &self.defmi_id,
                &self.rfq_nullifier,
                &self.asset_id,
                &self.reserve_asset_id,
                &self.quantity_commitment,
                &self.limit_price_commitment,
                &self.maximum_fee_commitment,
                &self.maximum_amount_commitment,
                &self.reserve_id,
                &self.entity_commitment,
                &self.kyb_presentation_digest,
                &self.admission_ticket_id,
                &self.taker_public,
            ])
        {
            return Err("Taker mandate is incomplete or cannot auto-settle".into());
        }
        let mut body = TAKER_DOMAIN.to_vec();
        for value in [
            &self.venue_id,
            &self.defmi_id,
            &self.rfq_nullifier,
            &self.asset_id,
            &self.reserve_asset_id,
        ] {
            body.extend_from_slice(value);
        }
        body.push(self.direction as u8);
        for value in [
            &self.quantity_commitment,
            &self.limit_price_commitment,
            &self.maximum_fee_commitment,
            &self.maximum_amount_commitment,
            &self.reserve_id,
            &self.taker_handle,
            &self.entity_commitment,
            &self.kyb_presentation_digest,
            &self.admission_ticket_id,
        ] {
            body.extend_from_slice(value);
        }
        body.extend_from_slice(&self.admission_slot.to_be_bytes());
        body.extend_from_slice(&self.deadline.to_be_bytes());
        body.push(u8::from(self.allow_partial));
        body.push(u8::from(self.auto_settle));
        body.extend_from_slice(&self.taker_public);
        Ok(body)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(self.unsigned()?)
            .chain_update(self.signature.to_bytes())
            .finalize()
            .into())
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self, String> {
        if self.taker_public != key.verifying_key().to_bytes() {
            return Err("Taker signing key does not match the mandate".into());
        }
        self.signature = key.sign(&self.unsigned()?);
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        presentation: &KybPresentation,
        registry: &SignedCohortRegistry,
        trusted_issuer: &VerifyingKey,
        kyb_scope: &[u8],
        kyb_context: &[u8],
        required_cohort: &str,
        now: u64,
    ) -> Result<(), String> {
        if now > self.deadline {
            return Err("Taker execution mandate has expired".into());
        }
        verify_presentation(
            presentation,
            registry,
            trusted_issuer,
            kyb_scope,
            kyb_context,
            now,
            required_cohort,
        )
        .map_err(|error| format!("Taker KYB presentation failed: {error:?}"))?;
        if self.kyb_presentation_digest != presentation.digest()
            || self.entity_commitment != presentation.entity_commitment()
        {
            return Err("Taker mandate is bound to another legal entity proof".into());
        }
        VerifyingKey::from_bytes(&self.taker_public)
            .map_err(|_| "Taker public key is malformed".to_string())?
            .verify(&self.unsigned()?, &self.signature)
            .map_err(|_| "Taker execution mandate signature is invalid".to_string())
    }
}

/// Digest arbitrary signed admission evidence without teaching this module a
/// second receipt codec.
pub fn admission_receipt_digest(receipt_bytes: &[u8]) -> Result<[u8; 32], String> {
    if receipt_bytes.is_empty() {
        return Err("admission receipt is empty".into());
    }
    let mut framed = Vec::new();
    push_bytes(&mut framed, receipt_bytes);
    Ok(Sha256::new()
        .chain_update(b"QOMM:MANDATE:ADMISSION-RECEIPT:v1")
        .chain_update(framed)
        .finalize()
        .into())
}
