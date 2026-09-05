//! Verifier-complete consumption of application-scoped covenant reservations.
//!
//! Arithmetic uses the existing threshold zkPI/DvP proofs. A separate FROST
//! certificate binds the exact application action, canonical parent and both
//! reservation heads. It is signed by the pre-authorized MPC committee, not
//! by the participants after seeing the match. Matching-policy correctness is
//! that committee's responsibility; this verifier checks the full monetary
//! proofs and the certificate, not a caller-supplied "verified" flag.

use crate::application_reservation::ApplicationReserveScope;
use crate::asset_link::{self, AssetLinkProof};
use crate::facility::ZERO;
use crate::note_chain::{note_claim_recipient_commitment, NoteClaim, NoteClaimKind};
use crate::settlement::{build_threshold_package_from_proofs, Sides};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use qomm_proofs::opening_envelope::{opening_context, EncryptedOpeningShare, OpeningEnvelope};
use qomm_transport::proof_codec::decode_dvp_proofs;
use qomm_zk::pedersen::Pedersen;
use qomm_zkpi::{frost, Bounds, QuoteBinding, Venue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FILL_DOMAIN: &[u8] = b"DEFMI:APPLICATION:NOTE-FILL:v1";
const RELEASE_DOMAIN: &[u8] = b"DEFMI:APPLICATION:NOTE-RELEASE:v1";
const MAX_PROOF_BYTES: usize = 1024 * 1024;

pub fn point(bytes: [u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(bytes)
        .decompress()
        .ok_or_else(|| "application settlement point is malformed".into())
}

fn scalar(bytes: [u8; 32]) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or_else(|| "application settlement scalar is not canonical".into())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationOpeningShare {
    pub party: u16,
    pub ephemeral: [u8; 32],
    pub masked_value: [u8; 32],
    pub masked_blinding: [u8; 32],
}

/// Public ciphertexts, never scalar openings or Shamir shares in the clear.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationOpening {
    pub context: [u8; 32],
    pub threshold: u16,
    pub recipient_view: [u8; 32],
    pub shares: Vec<ApplicationOpeningShare>,
}

impl ApplicationOpening {
    pub fn from_domain(value: &OpeningEnvelope) -> Result<Self, String> {
        value.validate()?;
        Ok(Self {
            context: value.context,
            threshold: value
                .threshold
                .try_into()
                .map_err(|_| "opening threshold exceeds u16")?,
            recipient_view: value.recipient_view.compress().to_bytes(),
            shares: value
                .shares
                .iter()
                .map(|share| {
                    Ok(ApplicationOpeningShare {
                        party: share
                            .party
                            .try_into()
                            .map_err(|_| "opening party exceeds u16")?,
                        ephemeral: share.ephemeral.compress().to_bytes(),
                        masked_value: share.masked_value.to_bytes(),
                        masked_blinding: share.masked_blinding.to_bytes(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        })
    }

    pub fn domain(&self) -> Result<OpeningEnvelope, String> {
        if self.shares.len() > 64 || self.context == ZERO {
            return Err("application opening is oversized or unbound".into());
        }
        OpeningEnvelope::new(
            self.context,
            self.threshold.into(),
            point(self.recipient_view)?,
            self.shares
                .iter()
                .map(|share| {
                    Ok(EncryptedOpeningShare {
                        party: share.party.into(),
                        ephemeral: point(share.ephemeral)?,
                        masked_value: scalar(share.masked_value)?,
                        masked_blinding: scalar(share.masked_blinding)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        )
    }

    /// Change only the blinding of a threshold-encrypted opening. Subtracting
    /// the same public delta from every polynomial evaluation changes its
    /// constant term by delta, without exposing any value or private share.
    pub fn subtract_reblinding(&self, delta: &Scalar) -> Result<Self, String> {
        let mut value = self.domain()?;
        for share in &mut value.shares {
            share.masked_blinding -= delta;
        }
        Self::from_domain(&value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationSpendHead {
    pub hold_id: [u8; 32],
    pub sequence: u64,
    pub previous_receipt: [u8; 32],
    pub remaining_commitment: [u8; 32],
    /// Revealed only once this certified match permits settlement disclosure.
    pub reserve_reblinding: [u8; 32],
    /// False keeps the remainder locked for further fills of the same order.
    pub close: bool,
}

impl ApplicationSpendHead {
    fn validate(&self) -> Result<(), String> {
        if self.hold_id == ZERO || self.previous_receipt == ZERO || self.sequence == u64::MAX {
            return Err("application reserve head is incomplete".into());
        }
        point(self.remaining_commitment)?;
        scalar(self.reserve_reblinding)?;
        Ok(())
    }
}

/// All fields except `signature` are bound by the authorized committee.
/// Securities and cash are explicit canonical rails; user identities and
/// orders are not present. The signed zkPI carries pseudonymous recipients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationNoteFill {
    pub version: u16,
    pub scope: ApplicationReserveScope,
    pub before_root: [u8; 32],
    pub operation_id: [u8; 32],
    pub mpc_result_digest: [u8; 32],
    pub securities_asset: [u8; 32],
    pub cash_asset: [u8; 32],
    pub securities: ApplicationSpendHead,
    pub cash: ApplicationSpendHead,
    pub instruction: Vec<u8>,
    pub dvp_proofs: Vec<u8>,
    pub cash_commitment: [u8; 32],
    pub asset_link_announcement: [u8; 32],
    pub asset_link_response: [u8; 32],
    /// Delivery and refund, first securities then cash.
    pub openings: [ApplicationOpening; 4],
    pub committee_public: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ApplicationNoteFill {
    pub fn signing_message(&self) -> Result<[u8; 32], String> {
        self.scope.validate()?;
        self.securities.validate()?;
        self.cash.validate()?;
        if self.version != 1
            || [
                self.before_root,
                self.operation_id,
                self.mpc_result_digest,
                self.securities_asset,
                self.cash_asset,
            ]
            .contains(&ZERO)
            || self.securities_asset == self.cash_asset
            || self.securities.hold_id == self.cash.hold_id
            || self.instruction.is_empty()
            || self.dvp_proofs.is_empty()
            || self.instruction.len() > MAX_PROOF_BYTES
            || self.dvp_proofs.len() > MAX_PROOF_BYTES
            || self.committee_public.is_empty()
            || self.committee_public.len() > 64 * 1024
            || self.signature.len() > 64
        {
            return Err("application fill is incomplete or oversized".into());
        }
        for opening in &self.openings {
            opening.domain()?;
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let raw = serde_json::to_vec(&unsigned).map_err(|error| error.to_string())?;
        if raw.len() > 2 * MAX_PROOF_BYTES {
            return Err("application fill exceeds its total wire bound".into());
        }
        Ok(Sha256::new()
            .chain_update(FILL_DOMAIN)
            .chain_update(raw)
            .finalize()
            .into())
    }

    pub fn verify(
        &self,
        expected_scope: &ApplicationReserveScope,
        now: u64,
    ) -> Result<VerifiedApplicationFill, String> {
        let statement = self.signing_message()?;
        if &self.scope != expected_scope
            || <[u8; 32]>::from(Sha256::digest(&self.committee_public))
                != expected_scope.committee_key_digest
        {
            return Err("application fill committee or scope is not the pre-authorized one".into());
        }
        let public = frost::keys::PublicKeyPackage::deserialize(&self.committee_public)
            .map_err(|_| "application committee key is malformed")?;
        let signature = frost::Signature::deserialize(&self.signature)
            .map_err(|_| "application fill signature is malformed")?;
        public
            .verifying_key()
            .verify(&statement, &signature)
            .map_err(|_| "application fill committee signature is invalid")?;
        let instruction =
            qomm_zkpi::wire::decode(&self.instruction).map_err(|error| error.to_string())?;
        if qomm_zkpi::wire::encode(&instruction) != self.instruction
            || instruction.quote_binding != QuoteBinding::ProofDigest(self.mpc_result_digest)
        {
            return Err("application zkPI names another MPC result".into());
        }
        let key = Pedersen::new(b"qomm:defmi:v1");
        let bounds = Bounds {
            amount_bits: usize::from(expected_scope.amount_bits),
            price_bits: usize::from(expected_scope.amount_bits),
            max_horizon: 3_600,
        };
        Venue::new(key.clone(), &bounds, public)
            .require_threshold_ranges()
            .verify(&instruction, now)
            .map_err(str::to_string)?;
        let link = AssetLinkProof {
            announcement: point(self.asset_link_announcement)?,
            response: scalar(self.asset_link_response)?,
        };
        if !asset_link::verify(
            &key,
            &self.securities_asset,
            &instruction.asset_commitment,
            &link,
        ) {
            return Err("application zkPI asset differs from its canonical securities rail".into());
        }
        let securities_delta = scalar(self.securities.reserve_reblinding)?;
        let cash_delta = scalar(self.cash.reserve_reblinding)?;
        let package = build_threshold_package_from_proofs(
            &key,
            instruction.clone(),
            Sides::of(&instruction),
            point(self.securities.remaining_commitment)? + key.h * securities_delta,
            point(self.cash.remaining_commitment)? + key.h * cash_delta,
            point(self.cash_commitment)?,
            decode_dvp_proofs(&self.dvp_proofs)?,
            usize::from(self.scope.amount_bits),
        )?;
        let remaining = [
            package.securities_remainder - key.h * securities_delta,
            package.cash_remainder - key.h * cash_delta,
        ];
        let recipients = [
            instruction.payer_handle,
            instruction.payee_handle,
            instruction.payee_handle,
            instruction.payer_handle,
        ];
        let names = [
            "securities_delivery",
            "securities_refund",
            "cash_delivery",
            "cash_refund",
        ];
        for index in 0..4 {
            if self.openings[index].recipient_view != recipients[index].compress().to_bytes()
                || self.openings[index].context
                    != opening_context(&instruction.nonce, names[index])?
            {
                return Err("application opening names another proof job or recipient".into());
            }
        }
        let normalized_openings = [
            self.openings[1].subtract_reblinding(&securities_delta)?,
            self.openings[3].subtract_reblinding(&cash_delta)?,
        ];
        let values = [instruction.amount_commitment, package.cash_commitment];
        let heads = [&self.securities, &self.cash];
        let assets = [self.securities_asset, self.cash_asset];
        let mut claims = Vec::new();
        for index in 0..2 {
            claims.push(application_claim(
                assets[index],
                heads[index].hold_id,
                values[index].compress().to_bytes(),
                instruction.nullifier(),
                NoteClaimKind::Delivery,
                &self.openings[index * 2],
            )?);
            if heads[index].close {
                claims.push(application_claim(
                    assets[index],
                    heads[index].hold_id,
                    remaining[index].compress().to_bytes(),
                    instruction.nullifier(),
                    NoteClaimKind::Refund,
                    &normalized_openings[index],
                )?);
            }
        }
        Ok(VerifiedApplicationFill {
            statement,
            nullifier: instruction.nullifier(),
            deadline: instruction.deadline,
            dvp_digest: package.digest(),
            consumed: values.map(|point| point.compress().to_bytes()),
            remaining: remaining.map(|point| point.compress().to_bytes()),
            normalized_openings,
            claims,
        })
    }
}

pub fn application_claim(
    asset_id: [u8; 32],
    source_hold_id: [u8; 32],
    value_commitment: [u8; 32],
    context: [u8; 32],
    kind: NoteClaimKind,
    opening: &ApplicationOpening,
) -> Result<NoteClaim, String> {
    point(value_commitment)?;
    let mut claim = NoteClaim {
        claim_id: ZERO,
        asset_id,
        source_hold_id,
        value_commitment,
        recipient_commitment: note_claim_recipient_commitment(
            opening.recipient_view,
            context,
            asset_id,
            source_hold_id,
            kind,
        )?,
        kind,
        opening_envelope: opening.domain()?,
    };
    claim.claim_id = claim.derived_id()?;
    claim.validate()?;
    Ok(claim)
}

pub struct VerifiedApplicationFill {
    pub statement: [u8; 32],
    pub nullifier: [u8; 32],
    pub deadline: u64,
    pub dvp_digest: [u8; 32],
    pub consumed: [[u8; 32]; 2],
    pub remaining: [[u8; 32]; 2],
    pub normalized_openings: [ApplicationOpening; 2],
    pub claims: Vec<NoteClaim>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationReleaseReason {
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationNoteRelease {
    pub scope: ApplicationReserveScope,
    pub before_root: [u8; 32],
    pub operation_id: [u8; 32],
    pub hold_id: [u8; 32],
    pub sequence: u64,
    pub previous_receipt: [u8; 32],
    pub reason: ApplicationReleaseReason,
    /// Required for ordered cancellation; empty for time-based expiry.
    pub committee_public: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ApplicationNoteRelease {
    pub fn signing_message(&self) -> Result<[u8; 32], String> {
        self.scope.validate()?;
        if [
            self.before_root,
            self.operation_id,
            self.hold_id,
            self.previous_receipt,
        ]
        .contains(&ZERO)
            || self.sequence == u64::MAX
            || self.committee_public.len() > 64 * 1024
            || self.signature.len() > 64
        {
            return Err("application release is malformed".into());
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(Sha256::new()
            .chain_update(RELEASE_DOMAIN)
            .chain_update(serde_json::to_vec(&unsigned).map_err(|error| error.to_string())?)
            .finalize()
            .into())
    }

    pub fn verify(
        &self,
        scope: &ApplicationReserveScope,
        valid_until: u64,
        now: u64,
    ) -> Result<[u8; 32], String> {
        let statement = self.signing_message()?;
        if &self.scope != scope {
            return Err("application release names another deployment".into());
        }
        match self.reason {
            ApplicationReleaseReason::Expired => {
                if now <= valid_until
                    || !self.committee_public.is_empty()
                    || !self.signature.is_empty()
                {
                    return Err(
                        "expiry needs an expired reservation and no discretionary signature".into(),
                    );
                }
            }
            ApplicationReleaseReason::Cancelled => {
                if <[u8; 32]>::from(Sha256::digest(&self.committee_public))
                    != scope.committee_key_digest
                {
                    return Err("cancellation is not from its pre-authorized committee".into());
                }
                let public = frost::keys::PublicKeyPackage::deserialize(&self.committee_public)
                    .map_err(|_| "cancellation key is malformed")?;
                let signature = frost::Signature::deserialize(&self.signature)
                    .map_err(|_| "cancellation signature is malformed")?;
                public
                    .verifying_key()
                    .verify(&statement, &signature)
                    .map_err(|_| "cancellation signature is invalid")?;
            }
        }
        Ok(statement)
    }
}
