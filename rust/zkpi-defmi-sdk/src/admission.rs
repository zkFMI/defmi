//! Reservation evidence safe to give to an individual matching node.
//!
//! The full settlement permit names an asset, facility and escrow note. Those
//! references can reveal the order side through the public ledger, so they
//! must not be included in each node's decrypted order share. This certificate
//! instead attests to the hiding commitments and a private, stable hold tag.

use crate::reservation::ReservationPermit;
use crate::{SdkError, SdkResult};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer as MacSigner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkfmi_crypto::{
    hybrid::signature::{HybridSigner, HybridVerifier},
    key::KeyPurpose,
    traits::{Signer, Verifier},
};

const DOMAIN: &[u8] = b"ZKPI:DEFMI:RESERVATION-ADMISSION:v2";
const TAG_DOMAIN: &[u8] = b"ZKPI:DEFMI:RESERVATION-PRIVATE-TAG:v1";
const MAX_WIRE_BYTES: usize = 32 * 1024;
const MAX_UNIX_TIME: u64 = 253_402_300_799;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationAdmission {
    pub version: u16,
    pub application_binding: [u8; 32],
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub order_commitment: [u8; 32],
    pub participant_handle: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub side_commitment: [u8; 32],
    /// HMAC under the issuer secret, scoped to DeFMI and the hold identifier.
    /// Reissuing a permit cannot create another spend allowance; individual
    /// nodes cannot enumerate public note IDs to recover this tag's preimage.
    pub reservation_nullifier: [u8; 32],
    /// Commits to the full signed permit kept under threshold encryption.
    pub authority_commitment: [u8; 32],
    pub valid_until: u64,
    pub signer_public: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ReservationAdmission {
    /// Called by the same trusted issuer that read the canonical reservation.
    /// Only the returned certificate may be disclosed to every matching node.
    pub fn from_permit(
        permit: &ReservationPermit,
        reserve_reblinding: &Scalar,
        signer: &HybridSigner,
        private_tag_key: &[u8; 32],
    ) -> SdkResult<Self> {
        permit.verify(
            permit.application_binding,
            permit.defmi_id,
            &signer.public_key(),
            permit.valid_until,
        )?;
        if *private_tag_key == [0; 32] {
            return Err(invalid("reservation tag key is required"));
        }
        let mac_key = PKey::hmac(private_tag_key);
        let mac_key = mac_key.map_err(|_| invalid("reservation tag key failed"))?;
        let mut mac = MacSigner::new(MessageDigest::sha256(), &mac_key)
            .map_err(|_| invalid("reservation tag initialization failed"))?;
        for part in [TAG_DOMAIN, &permit.defmi_id, &permit.reservation_id] {
            mac.update(part)
                .map_err(|_| invalid("reservation tag failed"))?;
        }
        let reservation_nullifier = mac
            .sign_to_vec()
            .map_err(|_| invalid("reservation tag failed"))?
            .try_into()
            .map_err(|_| invalid("reservation tag has an invalid length"))?;
        let mut admission = Self {
            version: 2,
            application_binding: permit.application_binding,
            venue_id: permit.venue_id,
            defmi_id: permit.defmi_id,
            order_commitment: permit.order_commitment,
            participant_handle: permit.participant_handle,
            amount_commitment: reblinded_amount(permit, reserve_reblinding)?,
            side_commitment: permit.side_commitment,
            reservation_nullifier,
            authority_commitment: permit.digest()?,
            valid_until: permit.valid_until,
            signer_public: signer.public_key(),
            signature: Vec::new(),
        };
        admission.signature = signer
            .sign(KeyPurpose::SettlementInstruction, &admission.body()?)
            .map_err(|_| invalid("reservation admission signing failed"))?;
        Ok(admission)
    }

    pub fn verify(
        &self,
        application: [u8; 32],
        defmi: [u8; 32],
        signer: &[u8],
        now: u64,
    ) -> SdkResult<()> {
        if self.application_binding != application
            || self.defmi_id != defmi
            || self.signer_public != signer
            || now > self.valid_until
        {
            return Err(invalid("reservation admission trust or lifetime mismatch"));
        }
        HybridVerifier
            .verify(
                KeyPurpose::SettlementInstruction,
                signer,
                &self.body()?,
                &self.signature,
            )
            .map_err(|_| invalid("reservation admission signature is invalid"))
    }

    pub fn verify_authority(
        &self,
        permit: &ReservationPermit,
        reserve_reblinding: &Scalar,
    ) -> SdkResult<()> {
        if self.authority_commitment != permit.digest()?
            || self.application_binding != permit.application_binding
            || self.venue_id != permit.venue_id
            || self.defmi_id != permit.defmi_id
            || self.order_commitment != permit.order_commitment
            || self.participant_handle != permit.participant_handle
            || self.amount_commitment != reblinded_amount(permit, reserve_reblinding)?
            || self.side_commitment != permit.side_commitment
            || self.valid_until != permit.valid_until
            || self.signer_public != permit.signer_public
        {
            return Err(invalid(
                "settlement authority differs from reservation admission",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> SdkResult<[u8; 32]> {
        if self.signature.len() != 3373 {
            return Err(invalid("reservation admission is not signed"));
        }
        Ok(Sha256::new()
            .chain_update(self.body()?)
            .chain_update(&self.signature)
            .finalize()
            .into())
    }

    pub fn encode(&self) -> SdkResult<Vec<u8>> {
        self.digest()?;
        let wire = serde_json::to_vec(self).map_err(|_| invalid("admission encoding failed"))?;
        if wire.len() > MAX_WIRE_BYTES {
            return Err(invalid("reservation admission exceeds its wire bound"));
        }
        Ok(wire)
    }

    pub fn decode(wire: &[u8]) -> SdkResult<Self> {
        if wire.is_empty() || wire.len() > MAX_WIRE_BYTES {
            return Err(invalid("reservation admission wire is outside its bound"));
        }
        let admission: Self = serde_json::from_slice(wire)
            .map_err(|_| invalid("reservation admission wire is malformed"))?;
        admission.digest()?;
        Ok(admission)
    }

    fn body(&self) -> SdkResult<Vec<u8>> {
        if self.version != 2
            || self.valid_until == 0
            || self.valid_until > MAX_UNIX_TIME
            || self.signature.len() > 3373
        {
            return Err(invalid("reservation admission header is invalid"));
        }
        let mut body = DOMAIN.to_vec();
        body.extend_from_slice(&self.version.to_be_bytes());
        for field in [
            self.application_binding,
            self.venue_id,
            self.defmi_id,
            self.order_commitment,
            self.participant_handle,
            self.amount_commitment,
            self.side_commitment,
            self.reservation_nullifier,
            self.authority_commitment,
        ] {
            if field == [0; 32] {
                return Err(invalid("reservation admission has a zero binding"));
            }
            body.extend_from_slice(&field);
        }
        for field in [
            self.participant_handle,
            self.amount_commitment,
            self.side_commitment,
        ] {
            if CompressedRistretto(field).decompress().is_none() {
                return Err(invalid("reservation admission point is malformed"));
            }
        }
        if self.signer_public.len() != 1984 {
            return Err(invalid("reservation admission requires a hybrid signer"));
        }
        body.extend_from_slice(&self.signer_public);
        body.extend_from_slice(&self.valid_until.to_be_bytes());
        Ok(body)
    }
}

fn invalid(message: &str) -> SdkError {
    SdkError::InvalidExecution(message.into())
}

fn reblinded_amount(permit: &ReservationPermit, reblinding: &Scalar) -> SdkResult<[u8; 32]> {
    if *reblinding == Scalar::ZERO {
        return Err(invalid(
            "admission needs a fresh nonzero reserve reblinding",
        ));
    }
    let canonical = CompressedRistretto(permit.amount_commitment)
        .decompress()
        .ok_or_else(|| invalid("canonical reserve commitment is malformed"))?;
    Ok(
        (canonical + qomm_zk::pedersen::Pedersen::new(b"qomm:defmi:v1").h * reblinding)
            .compress()
            .to_bytes(),
    )
}
