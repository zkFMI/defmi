//! Recipient-only recovery of an MPC-created Pedersen opening.
//!
//! Each proof node encrypts only its own Shamir evaluation under the
//! recipient's one-use view key. The coordinator may collect every
//! ciphertext but cannot decrypt one; the recipient decrypts any threshold
//! subset and interpolates the value and blinding at zero. A later caller must
//! still compare the recovered opening with the claim's Pedersen commitment.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;

use crate::threshold_sigma::{lagrange_at_zero, PartyId};

const MASK_DOMAIN: &[u8] = b"QOMM:MPC:CLAIM-OPENING-MASK:v1";
const ENVELOPE_DOMAIN: &[u8] = b"QOMM:MPC:CLAIM-OPENING-ENVELOPE:v1";

fn mask(
    context: &[u8; 32],
    party: PartyId,
    ephemeral: &RistrettoPoint,
    shared: &RistrettoPoint,
    label: &[u8],
) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(MASK_DOMAIN);
    hash.update(context);
    hash.update((party as u64).to_be_bytes());
    hash.update(ephemeral.compress().as_bytes());
    hash.update(shared.compress().as_bytes());
    hash.update((label.len() as u64).to_be_bytes());
    hash.update(label);
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedOpeningShare {
    pub party: PartyId,
    pub ephemeral: RistrettoPoint,
    pub masked_value: Scalar,
    pub masked_blinding: Scalar,
}

impl EncryptedOpeningShare {
    pub fn validate(&self) -> Result<(), String> {
        if self.party == 0 || self.ephemeral == RistrettoPoint::identity() {
            return Err("encrypted opening share has an invalid party or ephemeral key".into());
        }
        Ok(())
    }

    fn opening(&self, context: &[u8; 32], recipient_view_secret: &Scalar) -> (Scalar, Scalar) {
        let shared = self.ephemeral * recipient_view_secret;
        (
            self.masked_value - mask(context, self.party, &self.ephemeral, &shared, b"value"),
            self.masked_blinding - mask(context, self.party, &self.ephemeral, &shared, b"blinding"),
        )
    }
}

pub fn opening_context(job_id: &[u8; 32], leg: &str) -> Result<[u8; 32], String> {
    if !matches!(
        leg,
        "securities_delivery" | "securities_refund" | "cash_delivery" | "cash_refund"
    ) {
        return Err("claim opening leg is invalid".into());
    }
    let mut hash = sha2::Sha256::new();
    hash.update(ENVELOPE_DOMAIN);
    hash.update(b":context:");
    hash.update(job_id);
    hash.update((leg.len() as u64).to_be_bytes());
    hash.update(leg.as_bytes());
    Ok(hash.finalize().into())
}

pub fn encrypt_opening_share<R: RngCore + CryptoRng>(
    context: [u8; 32],
    party: PartyId,
    value_share: Scalar,
    blinding_share: Scalar,
    recipient_view: &RistrettoPoint,
    rng: &mut R,
) -> Result<EncryptedOpeningShare, String> {
    if party == 0 || *recipient_view == RistrettoPoint::identity() {
        return Err("opening share needs a party and recipient view key".into());
    }
    let ephemeral_secret = Scalar::random(&mut *rng);
    let ephemeral = G * ephemeral_secret;
    let shared = recipient_view * ephemeral_secret;
    Ok(EncryptedOpeningShare {
        party,
        ephemeral,
        masked_value: value_share + mask(&context, party, &ephemeral, &shared, b"value"),
        masked_blinding: blinding_share + mask(&context, party, &ephemeral, &shared, b"blinding"),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpeningEnvelope {
    pub context: [u8; 32],
    pub threshold: usize,
    pub recipient_view: RistrettoPoint,
    pub shares: Vec<EncryptedOpeningShare>,
}

impl OpeningEnvelope {
    pub fn new(
        context: [u8; 32],
        threshold: usize,
        recipient_view: RistrettoPoint,
        shares: Vec<EncryptedOpeningShare>,
    ) -> Result<Self, String> {
        let value = Self {
            context,
            threshold,
            recipient_view,
            shares,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.threshold == 0
            || self.shares.len() < self.threshold
            || self.shares.len() > 64
            || self.recipient_view == RistrettoPoint::identity()
        {
            return Err("opening envelope has invalid dimensions".into());
        }
        let mut parties = BTreeSet::new();
        for share in &self.shares {
            share.validate()?;
            if !parties.insert(share.party) {
                return Err("opening envelope repeats a proof party".into());
            }
        }
        Ok(())
    }

    /// Decrypt one exact threshold subset. Supplying more parties is rejected
    /// so callers cannot silently pick a convenient subset after one fails.
    pub fn decrypt(
        &self,
        recipient_view_secret: &Scalar,
        quorum: &[PartyId],
    ) -> Result<(Scalar, Scalar), String> {
        self.validate()?;
        if G * recipient_view_secret != self.recipient_view
            || quorum.len() != self.threshold
            || quorum.iter().copied().collect::<BTreeSet<_>>().len() != quorum.len()
        {
            return Err("claim opening uses another recipient or quorum".into());
        }
        let coefficients = lagrange_at_zero(quorum)?;
        let mut value = Scalar::ZERO;
        let mut blinding = Scalar::ZERO;
        for party in quorum {
            let share = self
                .shares
                .iter()
                .find(|share| share.party == *party)
                .ok_or_else(|| "claim opening quorum names an absent proof party".to_string())?;
            let (value_share, blinding_share) = share.opening(&self.context, recipient_view_secret);
            let coefficient = coefficients
                .get(party)
                .ok_or_else(|| "claim opening interpolation omitted a party".to_string())?;
            value += coefficient * value_share;
            blinding += coefficient * blinding_share;
        }
        Ok((value, blinding))
    }

    pub fn decrypt_u64(
        &self,
        recipient_view_secret: &Scalar,
        quorum: &[PartyId],
        bits: usize,
    ) -> Result<(u64, Scalar), String> {
        if bits == 0 || bits > 64 {
            return Err("claim opening amount range is outside the supported bound".into());
        }
        let (value, blinding) = self.decrypt(recipient_view_secret, quorum)?;
        // Scalars created from a u64 use the canonical little-endian encoding.
        // Recover that encoding directly instead of performing an O(2^bits)
        // search, which made a 32-bit settlement claim unusable in practice.
        let encoded = value.to_bytes();
        if encoded[8..].iter().any(|byte| *byte != 0) {
            return Err("claim opening is outside the u64 amount range".into());
        }
        let amount = u64::from_le_bytes(
            encoded[..8]
                .try_into()
                .expect("checked eight-byte scalar prefix"),
        );
        if bits < 64 && amount >= (1_u64 << bits) {
            return Err("claim opening is outside its declared amount range".into());
        }
        Ok((amount, blinding))
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        let mut hash = sha2::Sha256::new();
        hash.update(ENVELOPE_DOMAIN);
        hash.update(self.context);
        hash.update((self.threshold as u64).to_be_bytes());
        hash.update(self.recipient_view.compress().as_bytes());
        hash.update((self.shares.len() as u64).to_be_bytes());
        for share in &self.shares {
            hash.update((share.party as u64).to_be_bytes());
            hash.update(share.ephemeral.compress().as_bytes());
            hash.update(share.masked_value.to_bytes());
            hash.update(share.masked_blinding.to_bytes());
        }
        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_sigma::deal;
    use qomm_zk::pedersen::Pedersen;
    use rand_core::OsRng;

    #[test]
    fn recipient_recovers_any_threshold_subset_but_another_key_cannot() {
        let recipient = Scalar::from(77_u64);
        let other = Scalar::from(78_u64);
        let amount = 4_300_000_000_u64;
        let value = Scalar::from(amount);
        let blinding = Scalar::from(91_u64);
        let parties = (1..=7).collect::<Vec<_>>();
        let shares = deal(
            &Pedersen::new(b"opening-envelope-test"),
            &value,
            &blinding,
            &parties,
            2,
            &mut OsRng,
        )
        .unwrap();
        let context = opening_context(&[5_u8; 32], "cash_delivery").unwrap();
        let encrypted = parties
            .iter()
            .map(|party| {
                encrypt_opening_share(
                    context,
                    *party,
                    shares.value_shares[party],
                    shares.blinding_shares[party],
                    &(G * recipient),
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect();
        let envelope = OpeningEnvelope::new(context, 3, G * recipient, encrypted).unwrap();
        assert!(envelope.decrypt_u64(&recipient, &[1, 4, 7], 32).is_err());
        assert_eq!(
            envelope.decrypt_u64(&recipient, &[1, 4, 7], 64).unwrap(),
            (amount, blinding)
        );
        assert!(envelope.decrypt_u64(&recipient, &[1, 4, 7], 65).is_err());
        assert!(envelope.decrypt(&other, &[1, 4, 7]).is_err());
        assert!(envelope.decrypt(&recipient, &[1, 4]).is_err());
    }
}
