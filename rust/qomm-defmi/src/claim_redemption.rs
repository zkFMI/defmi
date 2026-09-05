//! Recipient-authorized conversion of a final entitlement into a spendable note.
//!
//! The existing FROST Ristretto255 single-signer implementation signs the exact
//! public claim/output/parent/domain. We do not publish the destination wallet
//! address, the amount opening, or a new recipient key: verification uses the
//! recipient view point already present in the canonical opening envelope.
//! This withdrawal-like step cannot reverse the preceding settlement.

use crate::facility::ZERO;
use crate::note_chain::{NoteClaim, NoteOutput};
use crate::notes::{Address, NoteLedger};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::frost;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"DEFMI:NOTE-CLAIM-REDEMPTION:v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoteClaimRedemption {
    pub domain: String,
    pub before_root: [u8; 32],
    pub operation_id: [u8; 32],
    pub claim_id: [u8; 32],
    pub output: NoteOutput,
    pub recipient_signature: Vec<u8>,
}

impl NoteClaimRedemption {
    pub fn signing_message(&self) -> Result<[u8; 32], String> {
        if self.domain.is_empty()
            || self.domain.len() > 128
            || !self.domain.is_ascii()
            || self.before_root == ZERO
            || self.operation_id == ZERO
            || self.claim_id == ZERO
            || self.output.lock_id != ZERO
        {
            return Err("claim redemption has invalid context or a locked output".into());
        }
        let output = self.output.body()?;
        let body = serde_json::json!({
            "domain": self.domain,
            "before_root": hex::encode(self.before_root),
            "operation_id": hex::encode(self.operation_id),
            "claim_id": hex::encode(self.claim_id),
            "output": output,
        });
        Ok(Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(serde_json::to_vec(&body).map_err(err)?)
            .finalize()
            .into())
    }

    /// The caller supplies a claim read from canonical state, never a
    /// coordinator's replacement claim. Status/replay checks belong to the VM.
    pub fn verify(&self, claim: &NoteClaim, domain: &str) -> Result<(), String> {
        claim.validate()?;
        if self.domain != domain
            || self.claim_id != claim.claim_id
            || self.output.asset_id != claim.asset_id
            || self.output.value_commitment != claim.value_commitment
            || self.recipient_signature.len() != 64
        {
            return Err("claim redemption changes the deployment or final entitlement".into());
        }
        let public = frost::VerifyingKey::deserialize(
            claim.opening_envelope.recipient_view.compress().as_bytes(),
        )
        .map_err(err)?;
        let signature = frost::Signature::deserialize(&self.recipient_signature).map_err(err)?;
        public
            .verify(&self.signing_message()?, &signature)
            .map_err(err)
    }
}

/// Only the recipient decrypts the opening and chooses a destination. The
/// public proof reuses the reviewed upstream Schnorr implementation, not the
/// legacy ownership challenge containing destination wallet keys.
#[allow(clippy::too_many_arguments)]
pub fn redeem_claim<R: RngCore + CryptoRng>(
    claim: &NoteClaim,
    key: &Pedersen,
    amount_bits: usize,
    recipient_secret: &Scalar,
    destination: &Address,
    quorum: &[usize],
    domain: &str,
    before_root: [u8; 32],
    operation_id: [u8; 32],
    rng: &mut R,
) -> Result<NoteClaimRedemption, String> {
    claim.validate()?;
    let signer = frost::SigningKey::deserialize(&recipient_secret.to_bytes()).map_err(err)?;
    let public = frost::VerifyingKey::from(&signer)
        .serialize()
        .map_err(err)?;
    if public.as_slice() != claim.opening_envelope.recipient_view.compress().as_bytes() {
        return Err("claim belongs to another recipient".into());
    }
    let (amount, blind) =
        claim
            .opening_envelope
            .decrypt_u64(recipient_secret, quorum, amount_bits)?;
    let commitment = CompressedRistretto(claim.value_commitment)
        .decompress()
        .ok_or("claim value commitment is malformed")?;
    if key.commit_u64(amount, &blind) != commitment {
        return Err("decrypted claim differs from its canonical value commitment".into());
    }
    let ledger = NoteLedger::new(key.clone(), amount_bits);
    let note = ledger.build_note(destination, amount, commitment, &blind, &mut *rng);
    let mut redemption = NoteClaimRedemption {
        domain: domain.into(),
        before_root,
        operation_id,
        claim_id: claim.claim_id,
        output: NoteOutput::from_note(&note, claim.asset_id, ZERO)?,
        recipient_signature: vec![],
    };
    redemption.recipient_signature = signer
        .sign(rng, &redemption.signing_message()?)
        .serialize()
        .map_err(err)?;
    redemption.verify(claim, domain)?;
    Ok(redemption)
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
