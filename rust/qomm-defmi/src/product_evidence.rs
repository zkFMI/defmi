//! Verifier-complete public evidence for one automatic QOMM settlement.
//!
//! The transaction carries proof bytes, but never a price, quantity, reserve
//! opening, pricing policy, inventory state, or asset blinding. Canonical
//! decoding here is shared by the Avalanche client and every Rust validator.

use crate::asset_link::AssetLinkProof;
use qomm_transport::order::{decode_execution_attestations, encode_execution_attestations};
use qomm_transport::proof_codec::{
    decode_dvp_proofs, decode_quote_verification, decode_threshold_range, encode_dvp_proofs,
    encode_quote_verification, encode_threshold_range,
};

const MAX_TYPED_BYTES: usize = 512 * 1024;
const MAX_QUOTE_BYTES: usize = 768 * 1024;
const MAX_LIMIT_BYTES: usize = 128 * 1024;
const MAX_DVP_BYTES: usize = 256 * 1024;
const MAX_EXECUTION_ATTESTATION_BYTES: usize = 16 * 1024;

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
}
