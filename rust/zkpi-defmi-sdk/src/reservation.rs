//! Application-neutral proof that a DeFMI reservation already exists.
//!
//! A confidential application sends this permit directly to its MPC nodes.
//! The public application coordinator needs only the permit digest.  In
//! particular, the permit binds a Pedersen commitment to the private side;
//! it never discloses whether the owner is buying or selling.

use crate::{SdkError, SdkResult};
use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PERMIT_DOMAIN: &[u8] = b"ZKPI:DEFMI:APPLICATION-RESERVATION-PERMIT:v2";
const PERMIT_DIGEST_DOMAIN: &[u8] = b"ZKPI:DEFMI:APPLICATION-RESERVATION-DIGEST:v2";
const PERMIT_VERSION: u16 = 2;
const MAX_WIRE_BYTES: usize = 16 * 1024;
const MAX_UNIX_TIME: u64 = 253_402_300_799;
const ZERO: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationRole {
    /// Inventory or cash committed by a standing liquidity provider.
    Maker,
    /// Inventory or cash committed when an arriving order is submitted.
    Taker,
}

impl ReservationRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Maker => 1,
            Self::Taker => 2,
        }
    }
}

/// DeFMI-signed, privacy-preserving reservation authority for one application
/// order.  The permit is intentionally application-neutral: QOMM, OCLOB, and
/// future SDK applications can use the same verifier without sharing their
/// private order schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationPermit {
    pub version: u16,
    pub role: ReservationRole,
    pub application_binding: [u8; 32],
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub canonical_state_root: [u8; 32],
    pub accepted_height: u64,
    pub order_commitment: [u8; 32],
    pub participant_handle: [u8; 32],
    /// Anonymous legal-entity commitment accepted by the identity boundary.
    /// It is not an account address and cannot be used to recover the owner.
    pub entity_commitment: [u8; 32],
    pub reservation_id: [u8; 32],
    pub facility_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount_commitment: [u8; 32],
    /// One-time covenant note locked by the canonical reservation. Settlement
    /// consumes this identifier rather than naming an owner account.
    pub escrow_note_id: [u8; 32],
    /// Scope under which the application committee may consume the covenant.
    pub delegation_digest: [u8; 32],
    /// Pedersen commitment to the private buy/sell tag.  Its opening remains
    /// in the participant wallet and is Shamir-shared with the MPC nodes.
    pub side_commitment: [u8; 32],
    pub authority_digest: [u8; 32],
    pub reserve_receipt_digest: [u8; 32],
    pub reservation_sequence: u64,
    pub valid_until: u64,
    pub signer_public: [u8; 32],
    pub signature: Vec<u8>,
}

impl ReservationPermit {
    pub fn validate(&self) -> SdkResult<()> {
        if self.version != PERMIT_VERSION
            || self.accepted_height == 0
            || self.valid_until == 0
            || self.valid_until > MAX_UNIX_TIME
            || self.signature.len() > 64
        {
            return Err(invalid("reservation permit header is invalid"));
        }
        for (name, value) in [
            ("application binding", self.application_binding),
            ("venue id", self.venue_id),
            ("DeFMI id", self.defmi_id),
            ("canonical state root", self.canonical_state_root),
            ("order commitment", self.order_commitment),
            ("participant handle", self.participant_handle),
            ("entity commitment", self.entity_commitment),
            ("reservation id", self.reservation_id),
            ("facility id", self.facility_id),
            ("asset id", self.asset_id),
            ("amount commitment", self.amount_commitment),
            ("escrow note id", self.escrow_note_id),
            ("delegation digest", self.delegation_digest),
            ("side commitment", self.side_commitment),
            ("authority digest", self.authority_digest),
            ("reserve receipt digest", self.reserve_receipt_digest),
            ("signer public key", self.signer_public),
        ] {
            if value == ZERO {
                return Err(invalid(format!("{name} cannot be zero")));
            }
        }
        for (name, point) in [
            ("participant handle", self.participant_handle),
            ("amount commitment", self.amount_commitment),
            ("side commitment", self.side_commitment),
        ] {
            if CompressedRistretto(point).decompress().is_none() {
                return Err(invalid(format!("{name} is not a canonical point")));
            }
        }
        VerifyingKey::from_bytes(&self.signer_public)
            .map_err(|_| invalid("reservation permit signer is malformed"))?;
        Ok(())
    }

    fn unsigned_body(&self) -> SdkResult<Vec<u8>> {
        self.validate()?;
        let mut body = Vec::with_capacity(PERMIT_DOMAIN.len() + 32 * 17 + 32);
        body.extend_from_slice(PERMIT_DOMAIN);
        body.extend_from_slice(&self.version.to_be_bytes());
        body.push(self.role.tag());
        for value in [
            self.application_binding,
            self.venue_id,
            self.defmi_id,
            self.canonical_state_root,
        ] {
            body.extend_from_slice(&value);
        }
        body.extend_from_slice(&self.accepted_height.to_be_bytes());
        for value in [
            self.order_commitment,
            self.participant_handle,
            self.entity_commitment,
            self.reservation_id,
            self.facility_id,
            self.asset_id,
            self.amount_commitment,
            self.escrow_note_id,
            self.delegation_digest,
            self.side_commitment,
            self.authority_digest,
            self.reserve_receipt_digest,
        ] {
            body.extend_from_slice(&value);
        }
        body.extend_from_slice(&self.reservation_sequence.to_be_bytes());
        body.extend_from_slice(&self.valid_until.to_be_bytes());
        body.extend_from_slice(&self.signer_public);
        Ok(body)
    }

    pub fn sign(mut self, key: &SigningKey) -> SdkResult<Self> {
        if self.signer_public != key.verifying_key().to_bytes() || !self.signature.is_empty() {
            return Err(invalid(
                "reservation permit signing key or initial signature is invalid",
            ));
        }
        self.signature = key.sign(&self.unsigned_body()?).to_bytes().to_vec();
        Ok(self)
    }

    pub fn verify(
        &self,
        expected_application: [u8; 32],
        expected_defmi: [u8; 32],
        trusted_signer: &VerifyingKey,
        now: u64,
    ) -> SdkResult<()> {
        if self.application_binding != expected_application
            || self.defmi_id != expected_defmi
            || self.signer_public != trusted_signer.to_bytes()
            || now > self.valid_until
            || self.signature.len() != 64
        {
            return Err(invalid(
                "reservation permit application, DeFMI, signer, time, or signature is invalid",
            ));
        }
        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|_| invalid("reservation permit signature is malformed"))?;
        trusted_signer
            .verify(&self.unsigned_body()?, &signature)
            .map_err(|_| invalid("reservation permit signature does not verify"))
    }

    pub fn digest(&self) -> SdkResult<[u8; 32]> {
        if self.signature.len() != 64 {
            return Err(invalid("reservation permit is not signed"));
        }
        Ok(Sha256::new()
            .chain_update(PERMIT_DIGEST_DOMAIN)
            .chain_update(self.unsigned_body()?)
            .chain_update(&self.signature)
            .finalize()
            .into())
    }

    pub fn encode(&self) -> SdkResult<Vec<u8>> {
        self.digest()?;
        let wire = serde_json::to_vec(self)
            .map_err(|error| invalid(format!("reservation permit cannot be encoded: {error}")))?;
        if wire.len() > MAX_WIRE_BYTES {
            return Err(invalid("reservation permit exceeds its wire bound"));
        }
        Ok(wire)
    }

    pub fn decode(wire: &[u8]) -> SdkResult<Self> {
        if wire.is_empty() || wire.len() > MAX_WIRE_BYTES {
            return Err(invalid("reservation permit wire is outside its bound"));
        }
        let permit: Self = serde_json::from_slice(wire)
            .map_err(|error| invalid(format!("reservation permit wire is invalid: {error}")))?;
        permit.digest()?;
        Ok(permit)
    }
}

fn invalid(message: impl Into<String>) -> SdkError {
    SdkError::InvalidExecution(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::oclob_manifest_v1;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn signed() -> (ReservationPermit, SigningKey) {
        let signer = SigningKey::from_bytes(&id(19));
        let permit = ReservationPermit {
            version: PERMIT_VERSION,
            role: ReservationRole::Taker,
            application_binding: oclob_manifest_v1().digest().unwrap(),
            venue_id: id(1),
            defmi_id: id(2),
            canonical_state_root: id(3),
            accepted_height: 9,
            order_commitment: id(4),
            participant_handle: (RISTRETTO_BASEPOINT_POINT * Scalar::from(5_u64))
                .compress()
                .to_bytes(),
            entity_commitment: id(20),
            reservation_id: id(6),
            facility_id: id(7),
            asset_id: id(8),
            amount_commitment: (RISTRETTO_BASEPOINT_POINT * Scalar::from(9_u64))
                .compress()
                .to_bytes(),
            escrow_note_id: id(21),
            delegation_digest: id(22),
            side_commitment: (RISTRETTO_BASEPOINT_POINT * Scalar::from(10_u64))
                .compress()
                .to_bytes(),
            authority_digest: id(11),
            reserve_receipt_digest: id(12),
            reservation_sequence: 3,
            valid_until: 2_000,
            signer_public: signer.verifying_key().to_bytes(),
            signature: Vec::new(),
        }
        .sign(&signer)
        .unwrap();
        (permit, signer)
    }

    #[test]
    fn signed_permit_round_trips_and_hides_side() {
        let (permit, signer) = signed();
        let application = oclob_manifest_v1().digest().unwrap();
        permit
            .verify(application, id(2), &signer.verifying_key(), 1_000)
            .unwrap();
        let wire = permit.encode().unwrap();
        assert!(!String::from_utf8_lossy(&wire).contains("buy"));
        assert!(!String::from_utf8_lossy(&wire).contains("sell"));
        let decoded = ReservationPermit::decode(&wire).unwrap();
        assert_eq!(decoded, permit);
        assert_eq!(decoded.digest().unwrap(), permit.digest().unwrap());
    }

    #[test]
    fn rejects_tampering_expiry_and_cross_application_replay() {
        let (permit, signer) = signed();
        let application = oclob_manifest_v1().digest().unwrap();
        assert!(permit
            .verify(application, id(2), &signer.verifying_key(), 2_001)
            .is_err());
        let mut tampered = permit.clone();
        tampered.reservation_id = id(99);
        assert!(tampered
            .verify(application, id(2), &signer.verifying_key(), 1_000)
            .is_err());
        assert!(permit
            .verify(id(88), id(2), &signer.verifying_key(), 1_000)
            .is_err());
    }
}
