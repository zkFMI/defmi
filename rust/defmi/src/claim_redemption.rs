//! Recipient-authorized conversion of a final entitlement into a spendable note.
//!
//! The existing FROST Ristretto255 single-signer implementation signs the exact
//! public claim/output/parent/domain. The claim commits a fresh hybrid public
//! key without publishing it; redemption reveals that one-time key and proves
//! both the existing recipient secret and its post-quantum authorization.
//! The destination address and amount opening stay private, and this
//! withdrawal-like step cannot reverse the preceding settlement.

use crate::facility::ZERO;
use crate::note_chain::{ClaimAuthorizationCommitment, NoteClaim, NoteOutput};
use crate::notes::{Address, NoteLedger};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use zkfmi_zk::pedersen::Pedersen;
use zkpi::frost;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkfmi_crypto::{
    hybrid::signature::{HybridSigner, HybridVerifier},
    key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
    suite::{Suite, SuiteId, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES},
    traits::{Signer as _, Verifier as _},
};

const DOMAIN: &[u8] = b"DEFMI:NOTE-CLAIM-REDEMPTION:v2";
const PARTICIPANT_DOMAIN: &[u8] = b"DEFMI:NOTE-CLAIM-AUTH-PARTICIPANT:v1";
const KEY_FINGERPRINT_DOMAIN: &[u8] = b"DEFMI:NOTE-CLAIM-AUTH-FINGERPRINT:v1";
const KEY_RECORD_DOMAIN: &[u8] = b"DEFMI:NOTE-CLAIM-AUTH-KEY-RECORD:v1";
pub const VERSION: u8 = 2;
pub const AUTHORIZATION_SUITE: Suite = Suite::new(SuiteId::Ed25519MlDsa65);

pub struct NoteClaimAuthorization {
    recipient_commitment: [u8; 32],
    signer: HybridSigner,
    key_record: KeyRecord,
}

impl NoteClaimAuthorization {
    /// Generates a fresh independent key for one claim. No participant,
    /// opening, or KEM secret is accepted as key material.
    pub fn generate(
        recipient_commitment: [u8; 32],
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, String> {
        Self::from_signer(
            recipient_commitment,
            not_before,
            not_after,
            HybridSigner::generate().map_err(err)?,
        )
    }

    /// Restores one independently generated signer from encrypted participant
    /// custody. Callers must fail when that custody record is absent instead of
    /// generating a replacement key for an already committed claim.
    pub fn from_signer(
        recipient_commitment: [u8; 32],
        not_before: u64,
        not_after: u64,
        signer: HybridSigner,
    ) -> Result<Self, String> {
        if recipient_commitment == ZERO || not_before >= not_after {
            return Err("claim authorization has an invalid binding or lifetime".into());
        }
        let fingerprint = claim_key_fingerprint(&signer.public_key())?;
        let key_record = KeyRecord {
            participant_id: claim_participant_id(recipient_commitment)?,
            key_id: claim_key_id(fingerprint)?,
            suite: AUTHORIZATION_SUITE,
            key_version: 1,
            purpose: KeyPurpose::SettlementInstruction,
            public_key: signer.public_key(),
            not_before,
            not_after,
            revoked_at: None,
            rotation_proof: None,
            dekyx_binding: None,
        };
        key_record.validate().map_err(err)?;
        Ok(Self {
            recipient_commitment,
            signer,
            key_record,
        })
    }

    pub fn commitment(&self) -> Result<ClaimAuthorizationCommitment, String> {
        claim_authorization_commitment(self.recipient_commitment, &self.key_record)
    }

    pub fn key_record(&self) -> &KeyRecord {
        &self.key_record
    }
}

pub fn claim_participant_id(recipient_commitment: [u8; 32]) -> Result<ParticipantId, String> {
    if recipient_commitment == ZERO {
        return Err("claim recipient commitment cannot be zero".into());
    }
    ParticipantId::new(format!(
        "claim:{}",
        hex::encode(
            Sha256::new()
                .chain_update(PARTICIPANT_DOMAIN)
                .chain_update(recipient_commitment)
                .finalize()
        )
    ))
    .map_err(err)
}

fn claim_key_id(fingerprint: [u8; 32]) -> Result<KeyId, String> {
    KeyId::new(format!("claim-key:{}", hex::encode(fingerprint))).map_err(err)
}

pub fn claim_key_fingerprint(public_key: &[u8]) -> Result<[u8; 32], String> {
    if public_key.len() != 32 + ML_DSA_65_PK_BYTES {
        return Err("claim authorization requires an Ed25519-ML-DSA-65 public key".into());
    }
    Ok(Sha256::new()
        .chain_update(KEY_FINGERPRINT_DOMAIN)
        .chain_update(public_key)
        .finalize()
        .into())
}

pub fn claim_authorization_commitment(
    recipient_commitment: [u8; 32],
    key: &KeyRecord,
) -> Result<ClaimAuthorizationCommitment, String> {
    let fingerprint = claim_key_fingerprint(&key.public_key)?;
    let key_record_commitment = Sha256::new()
        .chain_update(KEY_RECORD_DOMAIN)
        .chain_update(recipient_commitment)
        .chain_update(serde_json::to_vec(key).map_err(err)?)
        .finalize()
        .into();
    Ok(ClaimAuthorizationCommitment {
        key_record_commitment,
        key_fingerprint: fingerprint,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoteClaimRedemption {
    pub version: u8,
    pub domain: String,
    pub before_root: [u8; 32],
    pub operation_id: [u8; 32],
    pub claim_id: [u8; 32],
    pub output: NoteOutput,
    pub authorization_key: KeyRecord,
    pub recipient_signature: Vec<u8>,
    pub authorization_signature: Vec<u8>,
}

impl NoteClaimRedemption {
    pub fn signing_message(&self) -> Result<[u8; 32], String> {
        if self.version != VERSION
            || self.domain.is_empty()
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
            "version": self.version,
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
    pub fn verify(&self, claim: &NoteClaim, domain: &str, now: u64) -> Result<(), String> {
        claim.validate()?;
        if self.domain != domain
            || self.claim_id != claim.claim_id
            || self.output.asset_id != claim.asset_id
            || self.output.value_commitment != claim.value_commitment
            || self.recipient_signature.len() != 64
            || self.authorization_signature.len() != 64 + ML_DSA_65_SIG_BYTES
        {
            return Err("claim redemption changes the deployment or final entitlement".into());
        }
        self.authorization_key.valid_at(now).map_err(err)?;
        let fingerprint = claim_key_fingerprint(&self.authorization_key.public_key)?;
        if self.authorization_key.participant_id
            != claim_participant_id(claim.recipient_commitment)?
            || self.authorization_key.key_id != claim_key_id(fingerprint)?
            || self.authorization_key.suite != AUTHORIZATION_SUITE
            || self.authorization_key.key_version != 1
            || self.authorization_key.purpose != KeyPurpose::SettlementInstruction
            || self.authorization_key.rotation_proof.is_some()
            || self.authorization_key.dekyx_binding.is_some()
            || claim.authorization
                != claim_authorization_commitment(
                    claim.recipient_commitment,
                    &self.authorization_key,
                )?
        {
            return Err("claim redemption substituted its one-time authorization key".into());
        }
        let public = frost::VerifyingKey::deserialize(
            claim.opening_envelope.recipient_view.compress().as_bytes(),
        )
        .map_err(err)?;
        let signature = frost::Signature::deserialize(&self.recipient_signature).map_err(err)?;
        let statement = self.signing_message()?;
        let ownership = public.verify(&statement, &signature);
        let authorization = HybridVerifier.verify(
            KeyPurpose::SettlementInstruction,
            &self.authorization_key.public_key,
            &statement,
            &self.authorization_signature,
        );
        if ownership.is_err() || authorization.is_err() {
            return Err("claim redemption ownership or hybrid authorization is invalid".into());
        }
        Ok(())
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
    recipient_key: &zkfmi_crypto::hybrid::kem::HybridKemKey,
    destination: &Address,
    quorum: &[usize],
    domain: &str,
    before_root: [u8; 32],
    operation_id: [u8; 32],
    authorization: &NoteClaimAuthorization,
    valid_at: u64,
    rng: &mut R,
) -> Result<NoteClaimRedemption, String> {
    redeem_claim_inner(claim, key, amount_bits, recipient_secret, recipient_key, destination,
        quorum, domain, before_root, operation_id, authorization, valid_at, None, rng)
}

/// Recover the actual asset from its recipient-only ciphertext, validate its
/// opening against the canonical tag (also at value zero), and carry that
/// metadata into the new recipient note. The public entitlement stays fixed.
#[allow(clippy::too_many_arguments)]
pub fn redeem_confidential_claim<R: RngCore + CryptoRng>(
    claim: &NoteClaim,
    identity: &crate::confidential_notes::AssetIdentity,
    asset_opening: &zkfmi_crypto::sealed::SealedMessage,
    amount_bits: usize,
    recipient_secret: &Scalar,
    recipient_key: &zkfmi_crypto::hybrid::kem::HybridKemKey,
    destination: &Address,
    quorum: &[usize],
    domain: &str,
    before_root: [u8; 32],
    operation_id: [u8; 32],
    authorization: &NoteClaimAuthorization,
    valid_at: u64,
    rng: &mut R,
) -> Result<NoteClaimRedemption, String> {
    identity.validate()?;
    if claim.asset_id != identity.commitment { return Err("claim has another confidential asset identity".into()); }
    let payload = asset_opening.open(recipient_key, zkfmi_crypto::sealed::SealingPurpose::NoteOpening,
        &crate::confidential_notes::asset_opening_context(&claim.claim_id), 64).map_err(err)?;
    let asset_id: [u8; 32] = payload[..32].try_into().map_err(err)?;
    let gamma = crate::confidential_assets::scalar(&payload[32..].try_into().map_err(err)?)?;
    let key = crate::confidential_notes::key();
    let generator = crate::confidential_assets::generator(&asset_id);
    if (generator + key.h * gamma).compress().to_bytes() != identity.tag {
        return Err("decrypted claim asset differs from its canonical tag".into());
    }
    redeem_claim_inner(claim, &key.with_value_generator(generator), amount_bits, recipient_secret,
        recipient_key, destination, quorum, domain, before_root, operation_id, authorization, valid_at,
        Some((&asset_id, &gamma)), rng)
}

#[allow(clippy::too_many_arguments)]
fn redeem_claim_inner<R: RngCore + CryptoRng>(claim: &NoteClaim, key: &Pedersen, amount_bits: usize,
    recipient_secret: &Scalar, recipient_key: &zkfmi_crypto::hybrid::kem::HybridKemKey,
    destination: &Address, quorum: &[usize], domain: &str, before_root: [u8; 32], operation_id: [u8; 32],
    authorization: &NoteClaimAuthorization, valid_at: u64, asset: Option<(&[u8; 32], &Scalar)>,
    rng: &mut R) -> Result<NoteClaimRedemption, String> {
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
            .decrypt_u64(recipient_secret, recipient_key, quorum, amount_bits)?;
    let commitment = CompressedRistretto(claim.value_commitment)
        .decompress()
        .ok_or("claim value commitment is malformed")?;
    if key.commit_u64(amount, &blind) != commitment {
        return Err("decrypted claim differs from its canonical value commitment".into());
    }
    let ledger = NoteLedger::new(key.clone(), amount_bits);
    let note = if let Some((id, gamma)) = asset {
        ledger.build_confidential_note(destination, amount, commitment, &blind, id, gamma, &mut *rng)?
    } else { ledger.build_note(destination, amount, commitment, &blind, &mut *rng)? };
    let mut redemption = NoteClaimRedemption {
        version: VERSION,
        domain: domain.into(),
        before_root,
        operation_id,
        claim_id: claim.claim_id,
        output: NoteOutput::from_note(&note, claim.asset_id, ZERO)?,
        authorization_key: authorization.key_record.clone(),
        recipient_signature: vec![],
        authorization_signature: vec![],
    };
    if authorization.recipient_commitment != claim.recipient_commitment
        || authorization.commitment()? != claim.authorization
    {
        return Err("claim authorization belongs to another claim".into());
    }
    let statement = redemption.signing_message()?;
    redemption.recipient_signature = signer.sign(rng, &statement).serialize().map_err(err)?;
    redemption.authorization_signature = authorization
        .signer
        .sign(KeyPurpose::SettlementInstruction, &statement)
        .map_err(err)?;
    redemption.verify(claim, domain, valid_at)?;
    Ok(redemption)
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
