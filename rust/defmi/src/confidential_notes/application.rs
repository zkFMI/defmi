//! Confidential funding/claim adapters around the existing full threshold DvP
//! verifier. Monetary verification and 3-of-7 hybrid authorization stay intact.

use super::*;
use crate::application_settlement::{
    application_claim, ApplicationNoteFill, ApplicationOpening, VerifiedApplicationFill,
};
use crate::note_chain::{NoteClaim, NoteClaimKind};
use zkfmi_crypto::sealed::{SealedMessage, SealingPurpose};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimConversion {
    pub value_commitment: [u8; 32],
    /// Value and effective blinding under the real asset generator, encrypted
    /// using the existing threshold recipient-opening mechanism.
    pub opening: ApplicationOpening,
    /// Actual asset ID and tag blinding, independently sealed to that recipient.
    pub asset_opening: SealedMessage,
    pub value_link: ValueLink,
}

pub fn asset_opening_context(claim_id: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"DEFMI:CONFIDENTIAL:CLAIM-ASSET-OPENING:v1")
        .chain_update(claim_id)
        .finalize()
        .into()
}

pub fn seal_claim_asset(
    claim: &NoteClaim,
    recipient_public: &[u8],
    asset_id: &[u8; 32],
    gamma: &Scalar,
    tag: &[u8; 32],
) -> Result<SealedMessage, String> {
    if (crate::confidential_assets::generator(asset_id) + key().h * gamma)
        .compress()
        .to_bytes()
        != *tag
    {
        return Err("claim asset opening does not match its canonical tag".into());
    }
    let mut payload = zeroize::Zeroizing::new([0u8; 64]);
    payload[..32].copy_from_slice(asset_id);
    payload[32..].copy_from_slice(gamma.as_bytes());
    SealedMessage::seal(
        recipient_public,
        SealingPurpose::NoteOpening,
        &asset_opening_context(&claim.claim_id),
        payload.as_ref(),
    )
    .map_err(|e| e.to_string())
}

impl ClaimConversion {
    pub fn claim(
        &self,
        asset_commitment: [u8; 32],
        hold: [u8; 32],
        kind: NoteClaimKind,
    ) -> Result<NoteClaim, String> {
        self.asset_opening
            .validate(SealingPurpose::NoteOpening, 64)
            .map_err(|e| e.to_string())?;
        application_claim(
            asset_commitment,
            hold,
            self.value_commitment,
            kind,
            &self.opening,
        )
    }

    pub fn value_context(
        context: &[u8; 32],
        normalized: &[u8; 32],
        tag: &[u8; 32],
        value: &[u8; 32],
        opening: &ApplicationOpening,
    ) -> Result<[u8; 32], String> {
        digest(
            b"DEFMI:CONFIDENTIAL:CLAIM-VALUE:v1",
            &(context, normalized, tag, value, opening),
        )
    }

    pub fn verify(
        &self,
        normalized: &[u8; 32],
        tag: &[u8; 32],
        context: &[u8; 32],
    ) -> Result<(), String> {
        self.opening.domain()?;
        self.asset_opening
            .validate(SealingPurpose::NoteOpening, 64)
            .map_err(|e| e.to_string())?;
        self.value_link.verify(
            &key().g,
            &point(tag)?,
            &crate::application_settlement::point(*normalized)?,
            &point(&self.value_commitment)?,
            &Self::value_context(
                context,
                normalized,
                tag,
                &self.value_commitment,
                &self.opening,
            )?,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedRefund {
    pub conversion: ClaimConversion,
    pub context: [u8; 32],
}

/// All added proofs and ciphertexts are covered by the SAME pre-authorized
/// committee certificate. The inner v3 fill cannot execute on the old endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfidentialFill {
    pub fill: ApplicationNoteFill,
    pub securities_asset_link: AssetProof,
    /// Always includes both refunds, even when retained for a later fill or
    /// non-discretionary expiry. No new secret is required to release later.
    pub conversions: [ClaimConversion; 4],
}

impl ConfidentialFill {
    pub fn asset_context(fill: &ApplicationNoteFill) -> Result<[u8; 32], String> {
        digest(
            b"DEFMI:CONFIDENTIAL:FILL-ASSET:v1",
            &(
                fill.scope.statement()?,
                fill.before_root,
                fill.operation_id,
                fill.mpc_result_digest,
                <[u8; 32]>::from(Sha256::digest(&fill.instruction)),
                fill.securities_asset,
                fill.cash_asset,
            ),
        )
    }

    pub fn conversion_context(
        fill: &ApplicationNoteFill,
        index: usize,
    ) -> Result<[u8; 32], String> {
        if index >= 4 {
            return Err("confidential claim leg is out of bounds".into());
        }
        digest(
            b"DEFMI:CONFIDENTIAL:FILL-CLAIM:v1",
            &(
                Self::asset_context(fill)?,
                index as u8,
                if index < 2 {
                    &fill.securities
                } else {
                    &fill.cash
                },
            ),
        )
    }

    pub fn signing_message(&self) -> Result<[u8; 32], String> {
        if self.fill.version != 3
            || self.fill.batch.is_some()
            || self.fill.asset_link_announcement != ZERO
            || self.fill.asset_link_response != ZERO
        {
            return Err("confidential fill has a legacy link, batch or version".into());
        }
        digest(
            b"DEFMI:CONFIDENTIAL:APPLICATION-FILL:v1",
            &(
                self.fill.signing_message()?,
                &self.securities_asset_link,
                &self.conversions,
            ),
        )
    }

    pub fn verify(
        &self,
        scope: &ApplicationReserveScope,
        identities: [&AssetIdentity; 2],
        now: u64,
    ) -> Result<VerifiedConfidentialFill, String> {
        self.verify_inner(scope, identities, now, false)
    }

    /// Verify every public relation before a committee member signs the outer
    /// certificate. The member must also bind the candidate to its private job.
    /// This yields no native execution authorization.
    pub fn verify_unsigned(
        &self,
        scope: &ApplicationReserveScope,
        identities: [&AssetIdentity; 2],
        now: u64,
    ) -> Result<(), String> {
        self.verify_inner(scope, identities, now, true).map(|_| ())
    }

    fn verify_inner(
        &self,
        scope: &ApplicationReserveScope,
        identities: [&AssetIdentity; 2],
        now: u64,
        unsigned: bool,
    ) -> Result<VerifiedConfidentialFill, String> {
        let statement = self.signing_message()?;
        for (identity, expected) in identities
            .iter()
            .zip([self.fill.securities_asset, self.fill.cash_asset])
        {
            identity.validate()?;
            if identity.commitment != expected {
                return Err("confidential fill identity differs from its reservation".into());
            }
        }
        let instruction = zkpi::wire::decode(&self.fill.instruction).map_err(|e| e.to_string())?;
        self.securities_asset_link.verify(
            &key(),
            &identities[0].registry,
            &point(&identities[0].tag)?,
            Some(&instruction.asset_commitment),
            &Self::asset_context(&self.fill)?,
        )?;
        // Full signatures, quantity/price ranges, multiplication and both
        // normalized nonnegative remainders are verified by the existing core.
        let mut verified = if unsigned {
            self.fill
                .verify_unsigned_confidential(scope, now, statement)?
        } else {
            self.fill.verify_confidential(scope, now, statement)?
        };
        let normalized = [
            verified.consumed[0],
            verified.remaining[0],
            verified.consumed[1],
            verified.remaining[1],
        ];
        let expected_openings = [
            &self.fill.openings[0],
            &verified.normalized_openings[0],
            &self.fill.openings[2],
            &verified.normalized_openings[1],
        ];
        let mut claims = Vec::with_capacity(4);
        for index in 0..4 {
            let conversion = &self.conversions[index];
            let expected = expected_openings[index];
            if conversion.opening.context != expected.context
                || conversion.opening.recipient_view != expected.recipient_view
                || conversion.opening.claim_context != expected.claim_context
                || conversion.opening.claim_authorization != expected.claim_authorization
                || conversion.opening.threshold != expected.threshold
            {
                return Err(
                    "confidential conversion changes its authorized recipient or threshold".into(),
                );
            }
            conversion.verify(
                &normalized[index],
                &identities[index / 2].tag,
                &Self::conversion_context(&self.fill, index)?,
            )?;
            let head = if index < 2 {
                &self.fill.securities
            } else {
                &self.fill.cash
            };
            let kind = if index % 2 == 0 {
                NoteClaimKind::Delivery
            } else {
                NoteClaimKind::Refund
            };
            claims.push(conversion.claim(identities[index / 2].commitment, head.hold_id, kind)?);
        }
        verified.claims = claims
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                i % 2 == 0
                    || if *i < 2 {
                        self.fill.securities.close
                    } else {
                        self.fill.cash.close
                    }
            })
            .map(|(_, c)| c.clone())
            .collect();
        Ok(VerifiedConfidentialFill {
            verified,
            all_claims: claims,
            refunds: [1, 3].map(|index| RetainedRefund {
                conversion: self.conversions[index].clone(),
                context: Self::conversion_context(&self.fill, index)
                    .expect("bounded index already verified"),
            }),
        })
    }
}

pub struct VerifiedConfidentialFill {
    pub verified: VerifiedApplicationFill,
    pub all_claims: Vec<NoteClaim>,
    pub refunds: [RetainedRefund; 2],
}
