//! A paired zkPI for delivery-versus-payment across two DeFMI deployments.
//!
//! The full instruction is exchanged only between the authorised parties and
//! the MPC quorum. Each ledger receives a different projection digest, so the
//! two public records do not contain a shared trade identifier.

use sha2::{Digest, Sha256, Sha512};

use crate::{frost, typed::TradeDirection};

const INSTRUCTION_DOMAIN: &[u8] = b"QOMM:ZKPI:CROSS-DOMAIN-DVP:v1";
const PROJECTION_DOMAIN: &[u8] = b"QOMM:ZKPI:CROSS-DOMAIN-PROJECTION:v1";
const RELATION_DOMAIN: &[u8] = b"QOMM:ZKPI:CROSS-DOMAIN-RELATION:v1";
const EVENT_DOMAIN: &[u8] = b"QOMM:ZKPI:CROSS-DOMAIN-EVENT:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DvpSide {
    Cash = 1,
    Securities = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DvpEvent {
    Prepared = 1,
    Claimed = 2,
}

/// One private projection of the transfer to be executed on one DeFMI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DvpRail {
    pub network_id: u32,
    pub chain_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub local_leg_id: [u8; 32],
    pub asset_commitment: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub source_handle_commitment: [u8; 32],
    pub escrow_handle_commitment: [u8; 32],
    pub destination_handle_commitment: [u8; 32],
    pub reserve_transfer_digest: [u8; 32],
    pub claim_transfer_digest: [u8; 32],
    pub refund_transfer_digest: [u8; 32],
}

impl DvpRail {
    fn append_to(&self, hash: &mut Sha512) {
        hash.update(self.network_id.to_be_bytes());
        for value in [
            self.chain_id,
            self.defmi_id,
            self.local_leg_id,
            self.asset_commitment,
            self.amount_commitment,
            self.source_handle_commitment,
            self.escrow_handle_commitment,
            self.destination_handle_commitment,
            self.reserve_transfer_digest,
            self.claim_transfer_digest,
            self.refund_transfer_digest,
        ] {
            hash.update(value);
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        for value in [
            self.chain_id,
            self.defmi_id,
            self.local_leg_id,
            self.asset_commitment,
            self.amount_commitment,
            self.source_handle_commitment,
            self.escrow_handle_commitment,
            self.destination_handle_commitment,
            self.reserve_transfer_digest,
            self.claim_transfer_digest,
            self.refund_transfer_digest,
        ] {
            if value == [0u8; 32] {
                return Err("cross-domain DvP rail contains a zero commitment");
            }
        }
        if self.source_handle_commitment == self.escrow_handle_commitment
            || self.escrow_handle_commitment == self.destination_handle_commitment
        {
            return Err("cross-domain DvP rail does not move through distinct escrow");
        }
        Ok(())
    }
}

/// Private, jointly-authorised instruction from which both ledger projections
/// are derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossDomainDvpBody {
    pub venue_id: [u8; 32],
    pub direction: TradeDirection,
    pub rfq_nullifier: [u8; 32],
    pub quote_proof_digest: [u8; 32],
    pub market_statement_digest: [u8; 32],
    pub price_commitment: [u8; 32],
    pub relation_proof_digest: [u8; 32],
    pub cash: DvpRail,
    pub securities: DvpRail,
    pub arm_deadline: u64,
    pub claim_deadline: u64,
    pub refund_after: u64,
    pub release_condition: [u8; 32],
    /// A high-entropy value known to the quorum, not a public trade ID.
    pub private_pair_nonce: [u8; 32],
}

impl CrossDomainDvpBody {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.cash.validate()?;
        self.securities.validate()?;
        for value in [
            self.venue_id,
            self.rfq_nullifier,
            self.quote_proof_digest,
            self.market_statement_digest,
            self.price_commitment,
            self.relation_proof_digest,
            self.release_condition,
            self.private_pair_nonce,
        ] {
            if value == [0u8; 32] {
                return Err("cross-domain DvP instruction contains a zero commitment");
            }
        }
        if self.cash.network_id == self.securities.network_id
            && self.cash.chain_id == self.securities.chain_id
            && self.cash.defmi_id == self.securities.defmi_id
        {
            return Err("cross-domain DvP requires two different DeFMI deployments");
        }
        if self.cash.local_leg_id == self.securities.local_leg_id {
            return Err("cross-domain DvP legs must use different public identifiers");
        }
        if !(self.arm_deadline < self.claim_deadline && self.claim_deadline < self.refund_after) {
            return Err("cross-domain DvP deadlines must satisfy arm < claim < refund");
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 64], &'static str> {
        self.validate()?;
        let mut hash = Sha512::new();
        hash.update(INSTRUCTION_DOMAIN);
        hash.update(self.venue_id);
        hash.update([self.direction as u8]);
        hash.update(self.rfq_nullifier);
        hash.update(self.quote_proof_digest);
        hash.update(self.market_statement_digest);
        hash.update(self.price_commitment);
        hash.update(self.relation_proof_digest);
        self.cash.append_to(&mut hash);
        self.securities.append_to(&mut hash);
        hash.update(self.arm_deadline.to_be_bytes());
        hash.update(self.claim_deadline.to_be_bytes());
        hash.update(self.refund_after.to_be_bytes());
        hash.update(self.release_condition);
        hash.update(self.private_pair_nonce);
        Ok(hash.finalize().into())
    }

    /// Ledger-local public binding. Cash and securities yield unrelated values
    /// unless the observer already knows the full private instruction.
    pub fn projection_digest(&self, side: DvpSide) -> Result<[u8; 32], &'static str> {
        let rail = match side {
            DvpSide::Cash => &self.cash,
            DvpSide::Securities => &self.securities,
        };
        let mut hash = Sha256::new();
        hash.update(PROJECTION_DOMAIN);
        hash.update([side as u8]);
        hash.update(self.digest()?);
        hash.update(rail.network_id.to_be_bytes());
        hash.update(rail.chain_id);
        hash.update(rail.defmi_id);
        hash.update(rail.local_leg_id);
        Ok(hash.finalize().into())
    }

    pub fn relation_projection(&self, side: DvpSide) -> Result<[u8; 32], &'static str> {
        let mut hash = Sha256::new();
        hash.update(RELATION_DOMAIN);
        hash.update([side as u8]);
        hash.update(self.projection_digest(side)?);
        hash.update(self.relation_proof_digest);
        Ok(hash.finalize().into())
    }

    /// Opaque value expected by one destination ledger for an event on the
    /// other ledger. It is derived from the private instruction, so publishing
    /// it on the destination does not reveal the source leg identifier.
    pub fn event_binding(
        &self,
        destination: DvpSide,
        event: DvpEvent,
    ) -> Result<[u8; 32], &'static str> {
        let (source, target) = match destination {
            DvpSide::Cash => (&self.securities, &self.cash),
            DvpSide::Securities => (&self.cash, &self.securities),
        };
        let mut hash = Sha256::new();
        hash.update(EVENT_DOMAIN);
        hash.update([destination as u8, event as u8]);
        hash.update(self.digest()?);
        hash.update(source.local_leg_id);
        hash.update(target.local_leg_id);
        hash.update(target.network_id.to_be_bytes());
        hash.update(target.chain_id);
        hash.update(target.defmi_id);
        Ok(hash.finalize().into())
    }
}

#[derive(Clone)]
pub struct CrossDomainDvpInstruction {
    pub body: CrossDomainDvpBody,
    /// FROST signature produced by the MPC/zkPI issuer quorum.
    pub authorization: frost::Signature,
}

impl CrossDomainDvpInstruction {
    pub fn verify(
        &self,
        public_key_package: &frost::keys::PublicKeyPackage,
    ) -> Result<(), &'static str> {
        let digest = self.body.digest()?;
        public_key_package
            .verifying_key()
            .verify(&digest, &self.authorization)
            .map_err(|_| "cross-domain DvP zkPI authorization does not verify")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rail(marker: u8) -> DvpRail {
        DvpRail {
            network_id: marker as u32,
            chain_id: [marker; 32],
            defmi_id: [marker + 10; 32],
            local_leg_id: [marker + 20; 32],
            asset_commitment: [marker + 30; 32],
            amount_commitment: [marker + 40; 32],
            source_handle_commitment: [marker + 50; 32],
            escrow_handle_commitment: [marker + 51; 32],
            destination_handle_commitment: [marker + 52; 32],
            reserve_transfer_digest: [marker + 53; 32],
            claim_transfer_digest: [marker + 54; 32],
            refund_transfer_digest: [marker + 55; 32],
        }
    }

    fn body() -> CrossDomainDvpBody {
        CrossDomainDvpBody {
            venue_id: [1; 32],
            direction: TradeDirection::TakerBuys,
            rfq_nullifier: [2; 32],
            quote_proof_digest: [3; 32],
            market_statement_digest: [4; 32],
            price_commitment: [5; 32],
            relation_proof_digest: [6; 32],
            cash: rail(10),
            securities: rail(20),
            arm_deadline: 100,
            claim_deadline: 200,
            refund_after: 300,
            release_condition: [7; 32],
            private_pair_nonce: [8; 32],
        }
    }

    #[test]
    fn creates_distinct_ledger_projections_from_one_private_dvp() {
        let instruction = body();
        instruction.validate().unwrap();
        let cash = instruction.projection_digest(DvpSide::Cash).unwrap();
        let securities = instruction.projection_digest(DvpSide::Securities).unwrap();
        assert_ne!(cash, securities);
        assert_ne!(
            instruction.relation_projection(DvpSide::Cash).unwrap(),
            instruction
                .relation_projection(DvpSide::Securities)
                .unwrap()
        );
        assert_ne!(
            instruction
                .event_binding(DvpSide::Cash, DvpEvent::Prepared)
                .unwrap(),
            instruction
                .event_binding(DvpSide::Securities, DvpEvent::Prepared)
                .unwrap()
        );
        assert_ne!(
            instruction
                .event_binding(DvpSide::Cash, DvpEvent::Prepared)
                .unwrap(),
            instruction
                .event_binding(DvpSide::Cash, DvpEvent::Claimed)
                .unwrap()
        );
    }

    #[test]
    fn rejects_same_deployment_and_shared_public_leg_id() {
        let mut instruction = body();
        instruction.securities.network_id = instruction.cash.network_id;
        instruction.securities.chain_id = instruction.cash.chain_id;
        instruction.securities.defmi_id = instruction.cash.defmi_id;
        assert!(instruction.validate().is_err());

        let mut instruction = body();
        instruction.securities.local_leg_id = instruction.cash.local_leg_id;
        assert!(instruction.validate().is_err());
    }
}
