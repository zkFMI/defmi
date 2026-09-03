//! Governance-pinned verifier configuration for automatic QOMM settlement.
//!
//! Proof bytes arrive with a settlement transaction, but their public keys,
//! eligible Maker registry and circuit widths must not come from that same
//! untrusted transaction. This object is registered on the DeFMI L1 before an
//! RFQ epoch opens and is part of Avalanche consensus state.

use qomm_zkpi::frost;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"QOMM:DEFMI:SETTLEMENT-VERIFIER:v1";
const MAX_FROST_PACKAGE_BYTES: usize = 64 * 1024;
const ZERO: [u8; 32] = [0; 32];

pub fn settlement_verifier_key(venue_id: [u8; 32], epoch: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"QOMM:DEFMI:SETTLEMENT-VERIFIER-KEY:v1");
    hash.update(venue_id);
    hash.update(epoch.to_be_bytes());
    hash.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementVerifierConfig {
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub epoch: u64,
    pub quote_registry_digest: [u8; 32],
    pub quote_eligibility_bits: u16,
    pub quote_span_bits: u16,
    pub amount_bits: u16,
    pub price_bits: u16,
    pub max_horizon: u64,
    pub frost_public_package: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl SettlementVerifierConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.venue_id == ZERO
            || self.defmi_id == ZERO
            || self.epoch == 0
            || self.quote_registry_digest == ZERO
            || self.quote_eligibility_bits == 0
            || self.quote_eligibility_bits > 62
            || self.quote_span_bits == 0
            || self.quote_span_bits > 64
            || self.amount_bits == 0
            || self.amount_bits > 64
            || self.price_bits == 0
            || self.price_bits > 64
            || self.max_horizon == 0
            || self.valid_from == 0
            || self.valid_until < self.valid_from
            || self.valid_until > crate::MAX_UNIX_TIME
            || self.frost_public_package.is_empty()
            || self.frost_public_package.len() > MAX_FROST_PACKAGE_BYTES
        {
            return Err("settlement verifier configuration is outside its bounds".into());
        }
        let package = frost::keys::PublicKeyPackage::deserialize(&self.frost_public_package)
            .map_err(|_| "settlement verifier FROST package is invalid".to_string())?;
        if package
            .serialize()
            .map_err(|_| "settlement verifier FROST package cannot be serialized".to_string())?
            != self.frost_public_package
        {
            return Err("settlement verifier FROST package is not canonical".into());
        }
        Ok(())
    }

    pub fn key(&self) -> [u8; 32] {
        settlement_verifier_key(self.venue_id, self.epoch)
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(self.venue_id);
        hash.update(self.defmi_id);
        hash.update(self.epoch.to_be_bytes());
        hash.update(self.quote_registry_digest);
        hash.update(self.quote_eligibility_bits.to_be_bytes());
        hash.update(self.quote_span_bits.to_be_bytes());
        hash.update(self.amount_bits.to_be_bytes());
        hash.update(self.price_bits.to_be_bytes());
        hash.update(self.max_horizon.to_be_bytes());
        hash.update((self.frost_public_package.len() as u64).to_be_bytes());
        hash.update(&self.frost_public_package);
        hash.update(self.valid_from.to_be_bytes());
        hash.update(self.valid_until.to_be_bytes());
        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qomm_zkpi::deal_quorum;
    use rand_core::OsRng;

    #[test]
    fn config_is_canonical_and_keyed_by_venue_epoch() {
        let (_, public) = deal_quorum(7, 3, &mut OsRng).unwrap();
        let config = SettlementVerifierConfig {
            venue_id: [1; 32],
            defmi_id: [2; 32],
            epoch: 3,
            quote_registry_digest: [4; 32],
            quote_eligibility_bits: 32,
            quote_span_bits: 32,
            amount_bits: 16,
            price_bits: 32,
            max_horizon: 3_600,
            frost_public_package: public.serialize().unwrap(),
            valid_from: 10,
            valid_until: 20,
        };
        config.validate().unwrap();
        assert_ne!(config.key(), config.statement().unwrap());
    }
}
