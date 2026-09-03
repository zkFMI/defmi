//! Typed zkPI context for a streaming-receivable action.
//!
//! The base [`crate::Instruction`] hides and range-proves the economic values.
//! This context prevents those proofs from being moved to another stream,
//! provider combination, DeFMI note, guarantee hold, funding reservation, or
//! Aethel state root.

use curve25519_dalek::ristretto::CompressedRistretto;
use qomm_proofs::threshold_range::{verify_threshold_range, ThresholdRangeProof};
use sha2::{Digest, Sha256, Sha512};

use crate::{frost, wire, Instruction, Venue};

const DOMAIN: &[u8] = b"AETHEL:ZKPI:RECEIVABLE:v1";
const ELIGIBILITY_PROOF_DOMAIN: &[u8] = b"AETHEL:ZKPI:ELIGIBILITY-PROOF:v1";
pub const ELIGIBILITY_REMAINING_CONTEXT: &[u8] = b"aethel:eligibility-remaining:v1";
const ZERO: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReceivableOperation {
    Issue = 1,
    ClaimGuarantee = 2,
}

impl TryFrom<u8> for ReceivableOperation {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Issue),
            2 => Ok(Self::ClaimGuarantee),
            _ => Err("unknown streaming-receivable operation"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReference {
    pub artifact_id: [u8; 32],
    pub provider_id: [u8; 32],
    pub backing_id: [u8; 32],
}

impl ProviderReference {
    pub const fn absent() -> Self {
        Self {
            artifact_id: ZERO,
            provider_id: ZERO,
            backing_id: ZERO,
        }
    }

    pub fn is_absent(&self) -> bool {
        self.artifact_id == ZERO && self.provider_id == ZERO && self.backing_id == ZERO
    }

    pub fn is_complete(&self) -> bool {
        self.artifact_id != ZERO && self.provider_id != ZERO && self.backing_id != ZERO
    }
}

/// Public bindings around the private amount/price commitments.
///
/// `credit.backing_id` commits the registered model, policy, and decision proof,
/// `guarantee.backing_id` is the DeFMI guarantee hold, and
/// `funding.backing_id` is the DeFMI cash reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivableExecutionContext {
    pub operation: ReceivableOperation,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub verifier_epoch: u64,
    pub aethel_domain_id: [u8; 32],
    pub request_id: [u8; 32],
    pub action_id: [u8; 32],
    pub series_id: [u8; 32],
    pub stream_id: [u8; 32],
    pub stream_state_version: u64,
    pub before_stream_state_root: [u8; 32],
    pub after_stream_state_root: [u8; 32],
    pub eligible_commitment: [u8; 32],
    pub before_pledged_commitment: [u8; 32],
    pub after_pledged_commitment: [u8; 32],
    pub receivable_note_id: [u8; 32],
    pub settlement_asset_id: [u8; 32],
    pub credit: ProviderReference,
    pub guarantee: ProviderReference,
    pub funding: ProviderReference,
    pub policy_digest: [u8; 32],
    pub relation_proof_digest: [u8; 32],
    pub operation_nullifier: [u8; 32],
    pub before_aethel_root: [u8; 32],
}

impl ReceivableExecutionContext {
    pub fn validate_against(&self, instruction: &Instruction) -> Result<(), &'static str> {
        for value in [
            self.venue_id,
            self.defmi_id,
            self.aethel_domain_id,
            self.request_id,
            self.action_id,
            self.series_id,
            self.stream_id,
            self.before_stream_state_root,
            self.after_stream_state_root,
            self.eligible_commitment,
            self.after_pledged_commitment,
            self.receivable_note_id,
            self.settlement_asset_id,
            self.policy_digest,
            self.relation_proof_digest,
            self.operation_nullifier,
            self.before_aethel_root,
        ] {
            if value == ZERO {
                return Err("streaming-receivable zkPI has an empty required binding");
            }
        }
        if self.verifier_epoch == 0
            || self.stream_state_version == 0
            || instruction.payer_handle == instruction.payee_handle
        {
            return Err("streaming-receivable zkPI has an invalid epoch, version, or role mapping");
        }
        let quote = instruction
            .quote_proof_digest()
            .ok_or("streaming-receivable zkPI must use a proof-digest quote binding")?;
        if quote != self.relation_proof_digest {
            return Err("base zkPI and receivable context name different relation proofs");
        }
        for reference in [&self.credit, &self.guarantee, &self.funding] {
            if !(reference.is_absent() || reference.is_complete()) {
                return Err("provider artifact reference is only partially bound");
            }
        }
        match self.operation {
            ReceivableOperation::Issue => {
                if self.before_stream_state_root == self.after_stream_state_root {
                    return Err("receivable issuance must advance the pledged stream state");
                }
            }
            ReceivableOperation::ClaimGuarantee => {
                if !self.guarantee.is_complete() || !self.funding.is_absent() {
                    return Err("guarantee claim requires a guarantee and no funding quote");
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ReceivableInstruction {
    pub instruction: Instruction,
    pub context: ReceivableExecutionContext,
    /// A threshold proof that `eligible - pledged_after` is non-negative and
    /// fits the venue's published amount width. It is present only on issue.
    pub eligibility_remaining: Option<ThresholdRangeProof>,
    pub authorization: frost::Signature,
}

/// Canonically names the actual eligibility proof rather than an off-chain
/// assertion about it. The digest is also the base zkPI quote binding.
pub fn eligibility_relation_digest(proof: &ThresholdRangeProof) -> [u8; 32] {
    let encoded = wire::encode_threshold_range(proof);
    let mut hash = Sha256::new();
    hash.update(ELIGIBILITY_PROOF_DOMAIN);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    hash.finalize().into()
}

pub fn digest_for(
    instruction: &Instruction,
    context: &ReceivableExecutionContext,
    venue_domain: &[u8],
) -> Result<[u8; 64], &'static str> {
    context.validate_against(instruction)?;
    let mut hash = Sha512::new();
    hash.update(DOMAIN);
    hash.update((venue_domain.len() as u64).to_be_bytes());
    hash.update(venue_domain);
    hash.update(instruction.digest_for(venue_domain));
    hash.update([context.operation as u8]);
    hash.update(context.venue_id);
    hash.update(context.defmi_id);
    hash.update(context.verifier_epoch.to_be_bytes());
    hash.update(context.aethel_domain_id);
    hash.update(context.request_id);
    hash.update(context.action_id);
    hash.update(context.series_id);
    hash.update(context.stream_id);
    hash.update(context.stream_state_version.to_be_bytes());
    hash.update(context.before_stream_state_root);
    hash.update(context.after_stream_state_root);
    hash.update(context.eligible_commitment);
    hash.update(context.before_pledged_commitment);
    hash.update(context.after_pledged_commitment);
    hash.update(context.receivable_note_id);
    hash.update(context.settlement_asset_id);
    for reference in [&context.credit, &context.guarantee, &context.funding] {
        hash.update(reference.artifact_id);
        hash.update(reference.provider_id);
        hash.update(reference.backing_id);
    }
    hash.update(context.policy_digest);
    hash.update(context.relation_proof_digest);
    hash.update(context.operation_nullifier);
    hash.update(context.before_aethel_root);
    Ok(hash.finalize().into())
}

impl ReceivableInstruction {
    pub fn digest_for(&self, venue_domain: &[u8]) -> Result<[u8; 64], &'static str> {
        digest_for(&self.instruction, &self.context, venue_domain)
    }
}

impl Venue {
    pub fn verify_receivable(
        &self,
        instruction: &ReceivableInstruction,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify(&instruction.instruction, now)?;
        match instruction.context.operation {
            ReceivableOperation::Issue => {
                let proof = instruction
                    .eligibility_remaining
                    .as_ref()
                    .ok_or("receivable issuance has no eligibility-remaining proof")?;
                if proof.bits != self.amount_ranges.bits {
                    return Err("issued face value exceeds the eligible stream balance");
                }
                if eligibility_relation_digest(proof) != instruction.context.relation_proof_digest {
                    return Err("receivable eligibility proof digest does not match its binding");
                }
                let eligible = CompressedRistretto(instruction.context.eligible_commitment)
                    .decompress()
                    .ok_or("eligible commitment is not a Ristretto point")?;
                let before = CompressedRistretto(instruction.context.before_pledged_commitment)
                    .decompress()
                    .ok_or("pre-issuance pledged commitment is not a Ristretto point")?;
                let after = CompressedRistretto(instruction.context.after_pledged_commitment)
                    .decompress()
                    .ok_or("post-issuance pledged commitment is not a Ristretto point")?;
                if after.compress()
                    != (before + instruction.instruction.amount_commitment).compress()
                {
                    return Err("post-issuance pledged commitment does not add the face value");
                }
                let remaining = eligible - after;
                if !verify_threshold_range(
                    &self.key,
                    &remaining,
                    proof,
                    ELIGIBILITY_REMAINING_CONTEXT,
                ) {
                    return Err("issued face value exceeds the eligible stream balance");
                }
            }
            ReceivableOperation::ClaimGuarantee => {
                if instruction.eligibility_remaining.is_some() {
                    return Err("guarantee claim must not carry an issuance eligibility proof");
                }
            }
        }
        let digest = instruction.digest_for(&self.domain)?;
        self.group_public
            .verifying_key()
            .verify(&digest, &instruction.authorization)
            .map_err(|_| "streaming-receivable zkPI authorization does not verify")
    }
}
