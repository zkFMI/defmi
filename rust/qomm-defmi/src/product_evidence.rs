//! Verifier-complete public evidence for one automatic QOMM settlement.
//!
//! The transaction carries proof bytes, but never a price, quantity, reserve
//! opening, pricing policy, inventory state, or asset blinding. Canonical
//! decoding here is shared by the Avalanche client and every Rust validator.

use crate::asset_link::AssetLinkProof;
use qomm_transport::mandate::{decode_taker_mandate, encode_taker_mandate, TakerExecutionMandate};
use qomm_transport::mpc_result::{
    decode_public_result_attestations, encode_public_result_attestations, fill_mask_commitment,
    NodePublicResultAttestation,
};
use qomm_transport::order::{decode_execution_attestations, encode_execution_attestations};
use qomm_transport::proof_codec::{
    decode_dvp_proofs, decode_quote_verification, decode_threshold_range, encode_dvp_proofs,
    encode_quote_verification, encode_threshold_range,
};
use sha2::{Digest, Sha256};

const MAX_TYPED_BYTES: usize = 512 * 1024;
const MAX_QUOTE_BYTES: usize = 768 * 1024;
const MAX_LIMIT_BYTES: usize = 128 * 1024;
const MAX_DVP_BYTES: usize = 256 * 1024;
const MAX_EXECUTION_ATTESTATION_BYTES: usize = 16 * 1024;
const MAX_TAKER_MANDATE_BYTES: usize = 64 * 1024;
const NO_FILL_DOMAIN: &[u8] = b"QOMM:DEFMI:MPC-NO-FILL-EVIDENCE:v1";
const SETTLEMENT_EVIDENCE_DOMAIN: &[u8] = b"QOMM:DEFMI:PRODUCT-SETTLEMENT-EVIDENCE:v1";

#[derive(Clone, Debug)]
pub struct ProductSettlementEvidence {
    pub typed_instruction: Vec<u8>,
    pub quote_verification: Vec<u8>,
    pub price_limit_proof: Vec<u8>,
    pub dvp_proofs: Vec<u8>,
    /// Seven governance-key-signed receipts binding the complete quote proof
    /// to the exact node-local MP-SPDZ persistence files used by proof nodes.
    pub mpc_execution_attestations: Vec<u8>,
    pub asset_link: AssetLinkProof,
}

/// Validator-complete evidence that a pre-authorized Taker request produced no
/// executable fill. The only newly opened value is a one-time random mask;
/// price, limit, Maker identity, policy, inventory and note openings stay hidden.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MpcNoFillEvidence {
    pub signed_taker_mandate: Vec<u8>,
    pub public_result_attestations: Vec<u8>,
    pub fill_mask: u64,
}

impl MpcNoFillEvidence {
    pub fn validate_encoding(&self) -> Result<(), String> {
        bounded(
            &self.signed_taker_mandate,
            MAX_TAKER_MANDATE_BYTES,
            "signed Taker mandate",
        )?;
        bounded(
            &self.public_result_attestations,
            MAX_EXECUTION_ATTESTATION_BYTES,
            "public MPC result attestations",
        )?;
        if self.fill_mask == 0 {
            return Err("no-fill evidence cannot open a zero response mask".into());
        }
        let mandate = decode_taker_mandate(&self.signed_taker_mandate)?;
        if encode_taker_mandate(&mandate)? != self.signed_taker_mandate
            || mandate.fill_mask_commitment != fill_mask_commitment(self.fill_mask)
        {
            return Err("no-fill evidence does not open the pre-signed Taker mask".into());
        }
        let results = decode_public_result_attestations(&self.public_result_attestations)?;
        if encode_public_result_attestations(&results)? != self.public_result_attestations {
            return Err("public MPC result attestations are not canonically encoded".into());
        }
        Ok(())
    }

    pub fn mandate(&self) -> Result<TakerExecutionMandate, String> {
        self.validate_encoding()?;
        decode_taker_mandate(&self.signed_taker_mandate)
    }

    pub fn attestations(&self) -> Result<Vec<NodePublicResultAttestation>, String> {
        self.validate_encoding()?;
        decode_public_result_attestations(&self.public_result_attestations)
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.validate_encoding()?;
        let mut hash = Sha256::new();
        hash.update(NO_FILL_DOMAIN);
        hash.update((self.signed_taker_mandate.len() as u64).to_be_bytes());
        hash.update(&self.signed_taker_mandate);
        hash.update((self.public_result_attestations.len() as u64).to_be_bytes());
        hash.update(&self.public_result_attestations);
        hash.update(self.fill_mask.to_be_bytes());
        Ok(hash.finalize().into())
    }
}

fn bounded(raw: &[u8], maximum: usize, name: &str) -> Result<(), String> {
    if raw.is_empty() || raw.len() > maximum {
        Err(format!("{name} size is outside the settlement bound"))
    } else {
        Ok(())
    }
}

impl ProductSettlementEvidence {
    /// Reject non-canonical, trailing, malformed and single-prover encodings
    /// before a transaction is submitted. Validators repeat all proof checks;
    /// this method is an input-shape gate, not a consensus shortcut.
    pub fn validate_encoding(&self) -> Result<(), String> {
        bounded(
            &self.typed_instruction,
            MAX_TYPED_BYTES,
            "typed zkPI evidence",
        )?;
        bounded(
            &self.quote_verification,
            MAX_QUOTE_BYTES,
            "complete quote proof",
        )?;
        bounded(
            &self.price_limit_proof,
            MAX_LIMIT_BYTES,
            "price-limit proof",
        )?;
        bounded(&self.dvp_proofs, MAX_DVP_BYTES, "DvP proof")?;
        bounded(
            &self.mpc_execution_attestations,
            MAX_EXECUTION_ATTESTATION_BYTES,
            "MPC execution attestations",
        )?;

        let typed = qomm_zkpi::typed_wire::decode(&self.typed_instruction)
            .map_err(|error| format!("typed zkPI evidence is invalid: {error:?}"))?;
        if qomm_zkpi::typed_wire::encode(&typed) != self.typed_instruction {
            return Err("typed zkPI evidence is not canonically encoded".into());
        }

        let quote = decode_quote_verification(&self.quote_verification)?;
        if encode_quote_verification(&quote)? != self.quote_verification {
            return Err("complete quote proof is not canonically encoded".into());
        }

        let limit = decode_threshold_range(&self.price_limit_proof)?;
        if encode_threshold_range(&limit)? != self.price_limit_proof {
            return Err("price-limit proof is not canonically encoded".into());
        }

        let dvp = decode_dvp_proofs(&self.dvp_proofs)?;
        if encode_dvp_proofs(&dvp)? != self.dvp_proofs {
            return Err("DvP proof is not canonically encoded".into());
        }
        let executions = decode_execution_attestations(&self.mpc_execution_attestations)?;
        if encode_execution_attestations(&executions)? != self.mpc_execution_attestations {
            return Err("MPC execution attestations are not canonically encoded".into());
        }
        Ok(())
    }

    /// Bind the exact canonical proof bytes carried by an automatic
    /// settlement.  The product order already binds their public statements;
    /// this digest additionally prevents a governance-approved composite
    /// transaction from substituting a different valid proof encoding.
    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.validate_encoding()?;
        let mut hash = Sha256::new();
        hash.update(SETTLEMENT_EVIDENCE_DOMAIN);
        for field in [
            self.typed_instruction.as_slice(),
            self.quote_verification.as_slice(),
            self.price_limit_proof.as_slice(),
            self.dvp_proofs.as_slice(),
            self.mpc_execution_attestations.as_slice(),
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
        hash.update(self.asset_link.announcement.compress().as_bytes());
        hash.update(self.asset_link.response.as_bytes());
        Ok(hash.finalize().into())
    }
}
