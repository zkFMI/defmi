//! Product execution context for a zkPI.
//!
//! Version-one zkPI proves hidden amount and price and carries a quorum
//! signature, but deliberately says nothing about how the quote was selected.
//! QOMM needs that missing statement: both parties pre-authorised this exact
//! role mapping, the Maker reserve is current, and the quote proof and market
//! snapshot are the ones the quorum evaluated.  This wrapper signs the legacy
//! instruction digest together with those facts, preserving the deployed v1
//! codec while making the product path fail closed.

use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{Digest, Sha512};

use crate::{frost, Instruction, Venue};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperationKind {
    Reserve = 1,
    Consume = 2,
    Release = 3,
    Settle = 4,
}

impl TryFrom<u8> for OperationKind {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Reserve),
            2 => Ok(Self::Consume),
            3 => Ok(Self::Release),
            4 => Ok(Self::Settle),
            _ => Err("unknown typed zkPI operation"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TradeDirection {
    TakerBuys = 1,
    TakerSells = 2,
}

impl TryFrom<u8> for TradeDirection {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::TakerBuys),
            2 => Ok(Self::TakerSells),
            _ => Err("unknown typed zkPI direction"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthorizationScope {
    Maker = 1,
    Taker = 2,
    Joint = 3,
}

impl TryFrom<u8> for AuthorizationScope {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Maker),
            2 => Ok(Self::Taker),
            3 => Ok(Self::Joint),
            _ => Err("unknown typed zkPI authorization scope"),
        }
    }
}

#[derive(Clone)]
pub struct ExecutionContext {
    pub operation: OperationKind,
    pub scope: AuthorizationScope,
    pub direction: TradeDirection,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub maker_handle: RistrettoPoint,
    pub taker_handle: RistrettoPoint,
    pub reserve_handle: RistrettoPoint,
    pub maker_reservation_id: [u8; 32],
    pub maker_reservation_sequence: u64,
    pub taker_reservation_id: [u8; 32],
    pub taker_reservation_sequence: u64,
    pub rfq_nullifier: [u8; 32],
    pub taker_mandate_digest: [u8; 32],
    pub maker_policy_digest: [u8; 32],
    pub maker_mandate_digest: [u8; 32],
    pub maker_reserve_receipt_digest: [u8; 32],
    pub taker_reserve_receipt_digest: [u8; 32],
    pub quote_proof_digest: [u8; 32],
    pub market_statement_digest: [u8; 32],
    pub before_state_root: [u8; 32],
}

impl ExecutionContext {
    fn nonzero(value: &[u8; 32]) -> bool {
        value.iter().any(|byte| *byte != 0)
    }

    pub fn validate_against(&self, payment: &Instruction) -> Result<(), &'static str> {
        if self.maker_handle == self.taker_handle {
            return Err("Maker and Taker resolve to the same settlement handle");
        }
        if self.reserve_handle == self.maker_handle || self.reserve_handle == self.taker_handle {
            return Err("the reserve handle must not be a trading-party handle");
        }
        if !Self::nonzero(&self.before_state_root)
            || !Self::nonzero(&self.venue_id)
            || !Self::nonzero(&self.defmi_id)
        {
            return Err("typed zkPI lacks its venue, DeFMI, or prior state root");
        }
        match self.operation {
            OperationKind::Reserve => {
                let (owner, own_id, other_id, authority, forbidden_authority) = match self.scope {
                    AuthorizationScope::Maker => (
                        self.maker_handle,
                        &self.maker_reservation_id,
                        &self.taker_reservation_id,
                        &self.maker_policy_digest,
                        &self.taker_mandate_digest,
                    ),
                    AuthorizationScope::Taker => (
                        self.taker_handle,
                        &self.taker_reservation_id,
                        &self.maker_reservation_id,
                        &self.taker_mandate_digest,
                        &self.maker_policy_digest,
                    ),
                    AuthorizationScope::Joint => {
                        return Err("a reserve belongs to exactly one trading party")
                    }
                };
                if payment.payer_handle != owner || payment.payee_handle != self.reserve_handle {
                    return Err("reserve payer/payee do not move from its owner into escrow");
                }
                if !Self::nonzero(own_id)
                    || Self::nonzero(other_id)
                    || !Self::nonzero(authority)
                    || Self::nonzero(forbidden_authority)
                    || Self::nonzero(&self.maker_reserve_receipt_digest)
                    || Self::nonzero(&self.taker_reserve_receipt_digest)
                    || Self::nonzero(&self.quote_proof_digest)
                    || Self::nonzero(&self.market_statement_digest)
                {
                    return Err("reserve context contains missing or future execution data");
                }
                match self.scope {
                    AuthorizationScope::Maker if !Self::nonzero(&self.maker_mandate_digest) => {
                        return Err("Maker reserve lacks its signed policy mandate");
                    }
                    AuthorizationScope::Taker if Self::nonzero(&self.maker_mandate_digest) => {
                        return Err("Taker reserve contains an unrelated Maker mandate");
                    }
                    _ => {}
                }
                if self.scope == AuthorizationScope::Maker && Self::nonzero(&self.rfq_nullifier) {
                    return Err("a Maker reserve cannot claim a later RFQ");
                }
                if self.scope == AuthorizationScope::Taker && !Self::nonzero(&self.rfq_nullifier) {
                    return Err("a Taker reserve must bind its one-use RFQ");
                }
            }
            OperationKind::Release => {
                let (owner, own_id, other_id, receipt, other_receipt) = match self.scope {
                    AuthorizationScope::Maker => (
                        self.maker_handle,
                        &self.maker_reservation_id,
                        &self.taker_reservation_id,
                        &self.maker_reserve_receipt_digest,
                        &self.taker_reserve_receipt_digest,
                    ),
                    AuthorizationScope::Taker => (
                        self.taker_handle,
                        &self.taker_reservation_id,
                        &self.maker_reservation_id,
                        &self.taker_reserve_receipt_digest,
                        &self.maker_reserve_receipt_digest,
                    ),
                    AuthorizationScope::Joint => {
                        return Err("a release belongs to exactly one trading party")
                    }
                };
                if payment.payer_handle != self.reserve_handle || payment.payee_handle != owner {
                    return Err("release payer/payee do not return escrow to its owner");
                }
                if !Self::nonzero(own_id)
                    || Self::nonzero(other_id)
                    || !Self::nonzero(receipt)
                    || Self::nonzero(other_receipt)
                {
                    return Err("release lacks its unique reservation receipt");
                }
            }
            OperationKind::Consume | OperationKind::Settle => {
                if self.scope != AuthorizationScope::Joint {
                    return Err("settlement must jointly consume Maker and Taker authority");
                }
                if let Some(payment_quote) = payment.quote_proof_digest() {
                    if payment_quote != self.quote_proof_digest {
                        return Err(
                            "the payment zkPI and execution context name different quote proofs",
                        );
                    }
                }
                let role_mapping = match self.direction {
                    TradeDirection::TakerBuys => {
                        payment.payer_handle == self.taker_handle
                            && payment.payee_handle == self.maker_handle
                    }
                    TradeDirection::TakerSells => {
                        payment.payer_handle == self.maker_handle
                            && payment.payee_handle == self.taker_handle
                    }
                };
                if !role_mapping {
                    return Err("Maker/Taker roles do not match the payer/payee legs");
                }
                for (value, message) in [
                    (
                        &self.maker_reservation_id,
                        "settlement lacks the Maker reservation",
                    ),
                    (
                        &self.taker_reservation_id,
                        "settlement lacks the Taker reservation",
                    ),
                    (&self.rfq_nullifier, "settlement lacks the one-use RFQ"),
                    (
                        &self.taker_mandate_digest,
                        "settlement lacks the Taker mandate",
                    ),
                    (
                        &self.maker_mandate_digest,
                        "settlement lacks the Maker mandate",
                    ),
                    (
                        &self.maker_policy_digest,
                        "settlement lacks the Maker policy",
                    ),
                    (
                        &self.maker_reserve_receipt_digest,
                        "settlement lacks the Maker reserve receipt",
                    ),
                    (
                        &self.taker_reserve_receipt_digest,
                        "settlement lacks the Taker reserve receipt",
                    ),
                    (&self.quote_proof_digest, "settlement lacks the quote proof"),
                    (
                        &self.market_statement_digest,
                        "settlement lacks the reference-market statement",
                    ),
                ] {
                    if !Self::nonzero(value) {
                        return Err(message);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct TypedInstruction {
    pub payment: Instruction,
    pub context: ExecutionContext,
    /// A second FROST signature over `payment.digest || context`.  Keeping the
    /// v1 signature lets existing venues reject v2 cleanly while the product
    /// verifier requires both.
    pub authorization: frost::Signature,
}

pub fn digest_for(
    payment: &Instruction,
    context: &ExecutionContext,
    domain: &[u8],
) -> Result<[u8; 64], &'static str> {
    context.validate_against(payment)?;
    let mut hash = Sha512::new();
    hash.update(b"QOMM:ZKPI:TYPED:v1");
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update(payment.digest_for(domain));
    hash.update([
        context.operation as u8,
        context.scope as u8,
        context.direction as u8,
    ]);
    hash.update(context.venue_id);
    hash.update(context.defmi_id);
    hash.update(context.maker_handle.compress().as_bytes());
    hash.update(context.taker_handle.compress().as_bytes());
    hash.update(context.reserve_handle.compress().as_bytes());
    hash.update(context.maker_reservation_id);
    hash.update(context.maker_reservation_sequence.to_be_bytes());
    hash.update(context.taker_reservation_id);
    hash.update(context.taker_reservation_sequence.to_be_bytes());
    hash.update(context.rfq_nullifier);
    hash.update(context.taker_mandate_digest);
    hash.update(context.maker_policy_digest);
    hash.update(context.maker_mandate_digest);
    hash.update(context.maker_reserve_receipt_digest);
    hash.update(context.taker_reserve_receipt_digest);
    hash.update(context.quote_proof_digest);
    hash.update(context.market_statement_digest);
    hash.update(context.before_state_root);
    Ok(hash.finalize().into())
}

impl TypedInstruction {
    pub fn digest_for(&self, domain: &[u8]) -> Result<[u8; 64], &'static str> {
        digest_for(&self.payment, &self.context, domain)
    }
}

impl Venue {
    pub fn verify_typed(
        &self,
        instruction: &TypedInstruction,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify(&instruction.payment, now)?;
        let digest = instruction.digest_for(&self.domain)?;
        self.group_public
            .verifying_key()
            .verify(&digest, &instruction.authorization)
            .map_err(|_| "the typed zkPI authorization does not verify")
    }

    pub fn settle_typed(
        &mut self,
        instruction: &TypedInstruction,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify_typed(instruction, now)?;
        self.spent.insert(instruction.payment.nullifier());
        Ok(())
    }
}
