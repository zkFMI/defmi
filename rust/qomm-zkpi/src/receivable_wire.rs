//! Canonical wire format for a streaming-receivable zkPI.

use crate::receivable::{
    ProviderReference, ReceivableExecutionContext, ReceivableInstruction, ReceivableOperation,
};
use crate::{frost, wire};

pub const MAGIC: &[u8; 8] = b"AETHZKPI";
pub const VERSION: u16 = 1;
const MAX_BASE_BYTES: usize = 1_048_576;
const MAX_ELIGIBILITY_PROOF_BYTES: usize = 1_048_576;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    WrongMagic,
    UnknownVersion(u16),
    Truncated(&'static str),
    OversizedBase,
    OversizedEligibilityProof,
    InvalidBase,
    InvalidOperation,
    InvalidSignature,
    InvalidContext,
    Trailing(usize),
}

fn append_reference(output: &mut Vec<u8>, reference: &ProviderReference) {
    output.extend_from_slice(&reference.artifact_id);
    output.extend_from_slice(&reference.provider_id);
    output.extend_from_slice(&reference.backing_id);
}

fn append_context(output: &mut Vec<u8>, context: &ReceivableExecutionContext) {
    output.push(context.operation as u8);
    output.extend_from_slice(&context.venue_id);
    output.extend_from_slice(&context.defmi_id);
    output.extend_from_slice(&context.verifier_epoch.to_be_bytes());
    output.extend_from_slice(&context.aethel_domain_id);
    output.extend_from_slice(&context.request_id);
    output.extend_from_slice(&context.action_id);
    output.extend_from_slice(&context.series_id);
    output.extend_from_slice(&context.stream_id);
    output.extend_from_slice(&context.stream_state_version.to_be_bytes());
    output.extend_from_slice(&context.before_stream_state_root);
    output.extend_from_slice(&context.after_stream_state_root);
    output.extend_from_slice(&context.eligible_commitment);
    output.extend_from_slice(&context.before_pledged_commitment);
    output.extend_from_slice(&context.after_pledged_commitment);
    output.extend_from_slice(&context.receivable_note_id);
    output.extend_from_slice(&context.settlement_asset_id);
    append_reference(output, &context.credit);
    append_reference(output, &context.guarantee);
    append_reference(output, &context.funding);
    output.extend_from_slice(&context.policy_digest);
    output.extend_from_slice(&context.relation_proof_digest);
    output.extend_from_slice(&context.operation_nullifier);
    output.extend_from_slice(&context.before_aethel_root);
}

fn read_reference(reader: &mut Reader<'_>) -> Result<ProviderReference, Error> {
    Ok(ProviderReference {
        artifact_id: reader.id("provider artifact id")?,
        provider_id: reader.id("provider id")?,
        backing_id: reader.id("provider backing id")?,
    })
}

fn read_context(reader: &mut Reader<'_>) -> Result<ReceivableExecutionContext, Error> {
    let operation = ReceivableOperation::try_from(reader.take(1, "operation")?[0])
        .map_err(|_| Error::InvalidOperation)?;
    Ok(ReceivableExecutionContext {
        operation,
        venue_id: reader.id("venue id")?,
        defmi_id: reader.id("DeFMI id")?,
        verifier_epoch: reader.u64("verifier epoch")?,
        aethel_domain_id: reader.id("Aethel domain id")?,
        request_id: reader.id("request id")?,
        action_id: reader.id("action id")?,
        series_id: reader.id("series id")?,
        stream_id: reader.id("stream id")?,
        stream_state_version: reader.u64("stream state version")?,
        before_stream_state_root: reader.id("before stream state root")?,
        after_stream_state_root: reader.id("after stream state root")?,
        eligible_commitment: reader.id("eligible commitment")?,
        before_pledged_commitment: reader.id("before pledged commitment")?,
        after_pledged_commitment: reader.id("after pledged commitment")?,
        receivable_note_id: reader.id("receivable note id")?,
        settlement_asset_id: reader.id("settlement asset id")?,
        credit: read_reference(reader)?,
        guarantee: read_reference(reader)?,
        funding: read_reference(reader)?,
        policy_digest: reader.id("policy digest")?,
        relation_proof_digest: reader.id("relation proof digest")?,
        operation_nullifier: reader.id("operation nullifier")?,
        before_aethel_root: reader.id("before Aethel root")?,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize, name: &'static str) -> Result<&'a [u8], Error> {
        if self.at > self.bytes.len() || self.bytes.len() - self.at < length {
            return Err(Error::Truncated(name));
        }
        let value = &self.bytes[self.at..self.at + length];
        self.at += length;
        Ok(value)
    }

    fn id(&mut self, name: &'static str) -> Result<[u8; 32], Error> {
        self.take(32, name)?
            .try_into()
            .map_err(|_| Error::Truncated(name))
    }

    fn u64(&mut self, name: &'static str) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8, name)?
                .try_into()
                .map_err(|_| Error::Truncated(name))?,
        ))
    }

    fn u32(&mut self, name: &'static str) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4, name)?
                .try_into()
                .map_err(|_| Error::Truncated(name))?,
        ))
    }
}

pub fn encode(instruction: &ReceivableInstruction) -> Vec<u8> {
    let base = wire::encode(&instruction.instruction);
    let mut output = Vec::with_capacity(base.len() + 800);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&(base.len() as u32).to_be_bytes());
    output.extend_from_slice(&base);
    append_context(&mut output, &instruction.context);
    if let Some(proof) = &instruction.eligibility_remaining {
        let encoded = wire::encode_threshold_range(proof);
        output.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        output.extend_from_slice(&encoded);
    } else {
        output.extend_from_slice(&0u32.to_be_bytes());
    }
    output.extend_from_slice(
        &instruction
            .authorization
            .serialize()
            .expect("a FROST signature serializes"),
    );
    output
}

pub fn decode(bytes: &[u8]) -> Result<ReceivableInstruction, Error> {
    let mut reader = Reader { bytes, at: 0 };
    if reader.take(8, "magic")? != MAGIC {
        return Err(Error::WrongMagic);
    }
    let version = u16::from_be_bytes(
        reader
            .take(2, "version")?
            .try_into()
            .map_err(|_| Error::Truncated("version"))?,
    );
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }
    let base_length = u32::from_be_bytes(
        reader
            .take(4, "base length")?
            .try_into()
            .map_err(|_| Error::Truncated("base length"))?,
    ) as usize;
    if base_length > MAX_BASE_BYTES {
        return Err(Error::OversizedBase);
    }
    let instruction = wire::decode(reader.take(base_length, "base instruction")?)
        .map_err(|_| Error::InvalidBase)?;
    let context = read_context(&mut reader)?;
    let eligibility_length = reader.u32("eligibility proof length")? as usize;
    if eligibility_length > MAX_ELIGIBILITY_PROOF_BYTES {
        return Err(Error::OversizedEligibilityProof);
    }
    let eligibility_remaining = if eligibility_length == 0 {
        None
    } else {
        Some(
            wire::decode_threshold_range(reader.take(eligibility_length, "eligibility proof")?)
                .map_err(|_| Error::InvalidContext)?,
        )
    };
    let authorization = frost::Signature::deserialize(reader.take(64, "authorization")?)
        .map_err(|_| Error::InvalidSignature)?;
    if reader.at != bytes.len() {
        return Err(Error::Trailing(bytes.len() - reader.at));
    }
    context
        .validate_against(&instruction)
        .map_err(|_| Error::InvalidContext)?;
    if (context.operation == ReceivableOperation::Issue && eligibility_remaining.is_none())
        || (context.operation == ReceivableOperation::ClaimGuarantee
            && eligibility_remaining.is_some())
    {
        return Err(Error::InvalidContext);
    }
    Ok(ReceivableInstruction {
        instruction,
        context,
        eligibility_remaining,
        authorization,
    })
}
