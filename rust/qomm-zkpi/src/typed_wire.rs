//! Fixed wire format for a product-bound (typed) zkPI.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

use crate::typed::{
    AuthorizationScope, ExecutionContext, OperationKind, TradeDirection, TypedInstruction,
};
use crate::{frost, wire};

pub const MAGIC: &[u8; 8] = b"QOMMTZPI";
pub const VERSION: u16 = 1;
pub const CONTEXT_MAGIC: &[u8; 8] = b"QOMMCTX1";
pub const CONTEXT_VERSION: u16 = 1;
const MAX_BASE_BYTES: usize = 1_048_576;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    WrongMagic,
    UnknownVersion(u16),
    Truncated(&'static str),
    OversizedBase,
    InvalidBase,
    InvalidPoint(&'static str),
    InvalidOperation,
    InvalidScope,
    InvalidDirection,
    InvalidSignature,
    InvalidContext,
    Trailing(usize),
}

fn append_context(output: &mut Vec<u8>, context: &ExecutionContext) {
    output.push(context.operation as u8);
    output.push(context.scope as u8);
    output.push(context.direction as u8);
    output.extend_from_slice(&context.venue_id);
    output.extend_from_slice(&context.defmi_id);
    output.extend_from_slice(context.maker_handle.compress().as_bytes());
    output.extend_from_slice(context.taker_handle.compress().as_bytes());
    output.extend_from_slice(context.reserve_handle.compress().as_bytes());
    output.extend_from_slice(&context.maker_reservation_id);
    output.extend_from_slice(&context.maker_reservation_sequence.to_be_bytes());
    output.extend_from_slice(&context.taker_reservation_id);
    output.extend_from_slice(&context.taker_reservation_sequence.to_be_bytes());
    output.extend_from_slice(&context.rfq_nullifier);
    output.extend_from_slice(&context.taker_mandate_digest);
    output.extend_from_slice(&context.maker_policy_digest);
    output.extend_from_slice(&context.maker_mandate_digest);
    output.extend_from_slice(&context.maker_reserve_receipt_digest);
    output.extend_from_slice(&context.taker_reserve_receipt_digest);
    output.extend_from_slice(&context.quote_proof_digest);
    output.extend_from_slice(&context.market_statement_digest);
    output.extend_from_slice(&context.before_state_root);
}

fn read_context(reader: &mut Reader<'_>) -> Result<ExecutionContext, Error> {
    let operation = OperationKind::try_from(reader.take(1, "operation")?[0])
        .map_err(|_| Error::InvalidOperation)?;
    let scope = AuthorizationScope::try_from(reader.take(1, "scope")?[0])
        .map_err(|_| Error::InvalidScope)?;
    let direction = TradeDirection::try_from(reader.take(1, "direction")?[0])
        .map_err(|_| Error::InvalidDirection)?;
    let venue_id = reader.id("venue id")?;
    let defmi_id = reader.id("DeFMI id")?;
    let maker_handle = reader.point("maker handle")?;
    let taker_handle = reader.point("taker handle")?;
    let reserve_handle = reader.point("reserve handle")?;
    let maker_reservation_id = reader.id("Maker reservation id")?;
    let maker_reservation_sequence = u64::from_be_bytes(
        reader
            .take(8, "Maker reservation sequence")?
            .try_into()
            .map_err(|_| Error::Truncated("Maker reservation sequence"))?,
    );
    let taker_reservation_id = reader.id("Taker reservation id")?;
    let taker_reservation_sequence = u64::from_be_bytes(
        reader
            .take(8, "Taker reservation sequence")?
            .try_into()
            .map_err(|_| Error::Truncated("Taker reservation sequence"))?,
    );
    Ok(ExecutionContext {
        operation,
        scope,
        direction,
        venue_id,
        defmi_id,
        maker_handle,
        taker_handle,
        reserve_handle,
        maker_reservation_id,
        maker_reservation_sequence,
        taker_reservation_id,
        taker_reservation_sequence,
        rfq_nullifier: reader.id("RFQ nullifier")?,
        taker_mandate_digest: reader.id("Taker mandate digest")?,
        maker_policy_digest: reader.id("Maker policy digest")?,
        maker_mandate_digest: reader.id("Maker mandate digest")?,
        maker_reserve_receipt_digest: reader.id("Maker reserve receipt digest")?,
        taker_reserve_receipt_digest: reader.id("Taker reserve receipt digest")?,
        quote_proof_digest: reader.id("quote proof digest")?,
        market_statement_digest: reader.id("market statement digest")?,
        before_state_root: reader.id("before state root")?,
    })
}

/// Canonical context-only wire used when durable proof nodes authorize the
/// second, product-binding FROST signature after DeFMI reservations exist.
pub fn encode_context(context: &ExecutionContext) -> Vec<u8> {
    let mut output = Vec::with_capacity(541);
    output.extend_from_slice(CONTEXT_MAGIC);
    output.extend_from_slice(&CONTEXT_VERSION.to_be_bytes());
    append_context(&mut output, context);
    output
}

pub fn decode_context(
    bytes: &[u8],
    payment: &crate::Instruction,
) -> Result<ExecutionContext, Error> {
    let mut reader = Reader { bytes, at: 0 };
    if reader.take(8, "context magic")? != CONTEXT_MAGIC {
        return Err(Error::WrongMagic);
    }
    let version = u16::from_be_bytes(
        reader
            .take(2, "context version")?
            .try_into()
            .map_err(|_| Error::Truncated("context version"))?,
    );
    if version != CONTEXT_VERSION {
        return Err(Error::UnknownVersion(version));
    }
    let context = read_context(&mut reader)?;
    if reader.at != bytes.len() {
        return Err(Error::Trailing(bytes.len() - reader.at));
    }
    context
        .validate_against(payment)
        .map_err(|_| Error::InvalidContext)?;
    Ok(context)
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

    fn point(&mut self, name: &'static str) -> Result<RistrettoPoint, Error> {
        CompressedRistretto(self.id(name)?)
            .decompress()
            .ok_or(Error::InvalidPoint(name))
    }
}

pub fn encode(instruction: &TypedInstruction) -> Vec<u8> {
    let base = wire::encode(&instruction.payment);
    let context = &instruction.context;
    let mut output = Vec::with_capacity(base.len() + 408);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&(base.len() as u32).to_be_bytes());
    output.extend_from_slice(&base);
    append_context(&mut output, context);
    output.extend_from_slice(
        &instruction
            .authorization
            .serialize()
            .expect("a FROST signature serializes"),
    );
    output
}

pub fn decode(bytes: &[u8]) -> Result<TypedInstruction, Error> {
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
    let payment = wire::decode(reader.take(base_length, "base instruction")?)
        .map_err(|_| Error::InvalidBase)?;
    let context = read_context(&mut reader)?;
    let authorization = frost::Signature::deserialize(reader.take(64, "authorization")?)
        .map_err(|_| Error::InvalidSignature)?;
    if reader.at != bytes.len() {
        return Err(Error::Trailing(bytes.len() - reader.at));
    }
    context
        .validate_against(&payment)
        .map_err(|_| Error::InvalidContext)?;
    Ok(TypedInstruction {
        payment,
        context,
        authorization,
    })
}
