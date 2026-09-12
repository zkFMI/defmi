//! Asset-confidential extensions to the existing native note/application rail.
//!
//! The legacy `asset_id` slots carry an independently blinded asset commitment
//! in this version, never a plaintext identifier or its deterministic hash.
//! The versioned methods keep these notes away from the legacy fixed-G rail.
//! Mixed-asset rings use the unchanged parallel Triptych ownership/value core.

use crate::application_reservation::{
    ApplicationIdentityEvidence, ApplicationNoteReservation, ApplicationReservationBinding,
    ApplicationReserveMandate, ApplicationReserveScope,
};
use crate::confidential_assets::{point, scalar, AssetProof, Registry};
use crate::facility::ZERO;
use crate::facility::{CreditFacilityRelationProof, CreditFacilityTransition};
use crate::note_chain::{note_ring_root, CsdIssuerDefinition, NoteIssuance, NoteOutput, NoteSpend};
use crate::notes::{decode_spend_proof, Note, NoteLedger, SpendProof};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{RistrettoPoint, Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkfmi_zk::{
    pedersen::Pedersen,
    sigma::{self, CrossGeneratorProof},
};

pub const MAX_WIRE: usize = 2 * 1024 * 1024;

mod application;
pub use application::{
    asset_opening_context, seal_claim_asset, ClaimConversion, ConfidentialFill, RetainedRefund,
    VerifiedConfidentialFill,
};

pub fn key() -> Pedersen {
    Pedersen::new(b"qomm:defmi:v1")
}

pub fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > 8 * MAX_WIRE {
        return Err("confidential statement is oversized".into());
    }
    Ok(Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into())
}

/// Public asset identity for a facility or transfer. The cohort is public;
/// the selected asset and both independent blindings remain private.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetIdentity {
    pub commitment: [u8; 32],
    pub tag: [u8; 32],
    pub registry: Registry,
    pub proof: AssetProof,
}

impl AssetIdentity {
    fn context(
        commitment: &[u8; 32],
        tag: &[u8; 32],
        registry: &Registry,
    ) -> Result<[u8; 32], String> {
        digest(
            b"DEFMI:CONFIDENTIAL:ASSET-IDENTITY:v1",
            &(commitment, tag, registry.root()?),
        )
    }

    pub fn create<R: RngCore + CryptoRng>(
        registry: Registry,
        asset: &[u8; 32],
        gamma: &Scalar,
        rho: &Scalar,
        rng: &mut R,
    ) -> Result<Self, String> {
        let key = key();
        let tag = crate::confidential_assets::generator(asset) + key.h * gamma;
        let commitment = key.commit(&zkpi::asset_scalar(asset), rho);
        let context = Self::context(
            &commitment.compress().to_bytes(),
            &tag.compress().to_bytes(),
            &registry,
        )?;
        let proof = AssetProof::prove(
            &key,
            &registry,
            asset,
            &tag,
            gamma,
            Some((&commitment, rho)),
            &context,
            rng,
        )?;
        Ok(Self {
            commitment: commitment.compress().to_bytes(),
            tag: tag.compress().to_bytes(),
            registry,
            proof,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        self.proof.verify(
            &key(),
            &self.registry,
            &point(&self.tag)?,
            Some(&point(&self.commitment)?),
            &Self::context(&self.commitment, &self.tag, &self.registry)?,
        )
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        digest(b"DEFMI:CONFIDENTIAL:REGISTER-IDENTITY:v1", self)
    }
}

/// Canonical encoding of the existing cross-generator equality proof. Both
/// generators, commitments and the complete transition context are transcript-bound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValueLink {
    pub t_first: [u8; 32],
    pub t_second: [u8; 32],
    pub z_value: [u8; 32],
    pub z_first: [u8; 32],
    pub z_second: [u8; 32],
}

impl ValueLink {
    fn transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"DEFMI:CONFIDENTIAL:VALUE-LINK:v1");
        t.append_message(b"context", context);
        t
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        first_generator: &RistrettoPoint,
        second_generator: &RistrettoPoint,
        first: &RistrettoPoint,
        second: &RistrettoPoint,
        value: u64,
        first_blind: &Scalar,
        second_blind: &Scalar,
        context: &[u8],
        rng: &mut R,
    ) -> Result<Self, String> {
        let key = key();
        if key
            .with_value_generator(*first_generator)
            .commit_u64(value, first_blind)
            != *first
            || key
                .with_value_generator(*second_generator)
                .commit_u64(value, second_blind)
                != *second
        {
            return Err("value-link witness does not open both commitments".into());
        }
        let p = sigma::prove_same_value(
            &key,
            &mut Self::transcript(context),
            first_generator,
            second_generator,
            first,
            second,
            &Scalar::from(value),
            first_blind,
            second_blind,
            rng,
        );
        Ok(Self {
            t_first: p.t_first.compress().to_bytes(),
            t_second: p.t_second.compress().to_bytes(),
            z_value: p.z_value.to_bytes(),
            z_first: p.z_first.to_bytes(),
            z_second: p.z_second.to_bytes(),
        })
    }

    pub fn verify(
        &self,
        first_generator: &RistrettoPoint,
        second_generator: &RistrettoPoint,
        first: &RistrettoPoint,
        second: &RistrettoPoint,
        context: &[u8],
    ) -> Result<(), String> {
        let p = CrossGeneratorProof {
            t_first: point(&self.t_first)?,
            t_second: point(&self.t_second)?,
            z_value: scalar(&self.z_value)?,
            z_first: scalar(&self.z_first)?,
            z_second: scalar(&self.z_second)?,
        };
        if !sigma::verify_same_value(
            &key(),
            &mut Self::transcript(context),
            first_generator,
            second_generator,
            first,
            second,
            &p,
        ) {
            return Err("confidential value link failed".into());
        }
        Ok(())
    }
}

/// Reconstruct the ring from canonical outputs, including each member's own
/// asset commitment. Re-labelling all inputs with the output asset commitment
/// would derive different note IDs and cannot be used for a mixed-asset ring.
#[allow(clippy::too_many_arguments)]
pub fn verify_spend<R: RngCore + CryptoRng>(
    spend: &NoteSpend,
    proof: &SpendProof,
    identity: &AssetIdentity,
    canonical_ring: &[NoteOutput],
    bits: usize,
    context: &[u8],
    rng: &mut R,
) -> Result<(), String> {
    spend.validate()?;
    identity.validate()?;
    if !matches!(bits, 8 | 16 | 32 | 64)
        || canonical_ring.len() != spend.ring.len()
        || spend.asset_id != identity.commitment
        || proof.tag.compress().to_bytes() != identity.tag
        || proof.digest() != spend.proof_digest
        || proof.serial_point.compress().to_bytes() != spend.serial_point
    {
        return Err("confidential spend parameters, identity or proof digest differ".into());
    }
    let mut ledger = NoteLedger::new(key(), bits);
    let mut eligibility = Vec::with_capacity(canonical_ring.len());
    for (expected_id, output) in spend.ring.iter().zip(canonical_ring) {
        output.validate()?;
        if *expected_id != output.note_id {
            return Err("canonical mixed ring has a different member".into());
        }
        eligibility.push(output.lock_id == spend.input_lock_id);
        ledger.add(output.to_note()?);
    }
    let outputs = spend
        .outputs
        .iter()
        .map(NoteOutput::to_note)
        .collect::<Result<Vec<_>, _>>()?;
    if !proof.matches_output_notes(&outputs)
        || outputs.len() != proof.outputs.len()
        || outputs
            .iter()
            .zip(&proof.outputs)
            .any(|(n, c)| n.value_commitment != *c)
    {
        return Err("confidential spend substitutes an output or its ciphertext".into());
    }
    ledger
        .check_spend_constrained(
            &(0..canonical_ring.len()).collect::<Vec<_>>(),
            proof,
            &eligibility,
            context,
            rng,
        )
        .map_err(str::to_string)
}

#[allow(clippy::too_many_arguments)]
pub fn project_spend<R: RngCore + CryptoRng>(
    canonical_ring: &[NoteOutput],
    proof: &SpendProof,
    notes: &[Note],
    identity: &AssetIdentity,
    input_lock_id: [u8; 32],
    output_locks: &[[u8; 32]],
    bits: usize,
    context: &[u8],
    rng: &mut R,
) -> Result<NoteSpend, String> {
    if notes.len() != output_locks.len() {
        return Err("output lock dimensions differ".into());
    }
    let ring = canonical_ring.iter().map(|n| n.note_id).collect::<Vec<_>>();
    let spend = NoteSpend {
        asset_id: identity.commitment,
        ring_root: note_ring_root(identity.commitment, &ring)?,
        ring,
        serial_point: proof.serial_point.compress().to_bytes(),
        input_lock_id,
        proof_digest: proof.digest(),
        outputs: notes
            .iter()
            .zip(output_locks)
            .map(|(n, lock)| NoteOutput::from_note(n, identity.commitment, *lock))
            .collect::<Result<Vec<_>, _>>()?,
    };
    verify_spend(&spend, proof, identity, canonical_ring, bits, context, rng)?;
    Ok(spend)
}

#[derive(Clone)]
pub struct ConfidentialIssuance {
    pub issuance: NoteIssuance,
    pub identity: AssetIdentity,
    pub amount_bits: u16,
    pub range_proof: Vec<u8>,
}

impl ConfidentialIssuance {
    pub fn range_context(
        issuance: &NoteIssuance,
        identity: &AssetIdentity,
        amount_bits: u16,
    ) -> Result<[u8; 32], String> {
        digest(
            b"DEFMI:CONFIDENTIAL:ISSUE-RANGE:v1",
            &(
                issuance.operation_id,
                issuance.issuance_nonce,
                issuance.issuer_id,
                issuance.issued_at,
                issuance.output.body()?,
                identity.statement()?,
                amount_bits,
            ),
        )
    }

    fn transcript(context: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"DEFMI:CONFIDENTIAL:ISSUE-RANGE:v1");
        t.append_message(b"context", context);
        t
    }

    pub fn prove_range<R: RngCore + CryptoRng>(
        issuance: &NoteIssuance,
        identity: &AssetIdentity,
        bits: u16,
        amount: u64,
        tag_blinding: &Scalar,
        rng: &mut R,
    ) -> Result<Vec<u8>, String> {
        if !matches!(bits, 8 | 16 | 32 | 64) {
            return Err("unsupported confidential issuance range".into());
        }
        let k = key();
        let tag = point(&identity.tag)?;
        if k.with_value_generator(tag)
            .commit_u64(amount, tag_blinding)
            .compress()
            .to_bytes()
            != issuance.output.value_commitment
        {
            return Err("issuance value does not match its witness".into());
        }
        let (p, c) = RangeProof::prove_single_with_rng(
            &BulletproofGens::new(usize::from(bits), 1),
            &PedersenGens {
                B: tag,
                B_blinding: k.h,
            },
            &mut Self::transcript(&Self::range_context(issuance, identity, bits)?),
            amount,
            tag_blinding,
            usize::from(bits),
            rng,
        )
        .map_err(|e| e.to_string())?;
        if c.to_bytes() != issuance.output.value_commitment {
            return Err("issuance range commitment differs".into());
        }
        Ok(p.to_bytes())
    }

    pub fn proof_digest(&self) -> Result<[u8; 32], String> {
        digest(
            b"DEFMI:CONFIDENTIAL:ISSUE-PROOFS:v1",
            &(
                &self.identity,
                self.amount_bits,
                <[u8; 32]>::from(Sha256::digest(&self.range_proof)),
            ),
        )
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        if self.range_proof.len() > 8192
            || self.range_proof.is_empty()
            || !matches!(self.amount_bits, 8 | 16 | 32 | 64)
            || self.issuance.output.asset_id != self.identity.commitment
            || self.issuance.proof_digest != self.proof_digest()?
        {
            return Err("confidential issuance has unbound identity or proof bytes".into());
        }
        digest(
            b"DEFMI:CONFIDENTIAL:ISSUE:v1",
            &(self.issuance.body()?, self.proof_digest()?),
        )
    }

    pub fn verify(&self, issuer: &CsdIssuerDefinition, now: u64) -> Result<(), String> {
        use zkfmi_crypto::traits::Verifier as _;
        self.statement()?;
        self.identity.validate()?;
        issuer.body()?;
        // The issuer cohort, not an arbitrary prover-selected subset. A
        // single-asset issuer cannot offer asset anonymity at public issuance.
        if self.identity.registry.assets != issuer.permitted_asset_ids
            || self.issuance.issuer_id != issuer.issuer_id
            || self.issuance.issued_at > now
            || now.saturating_sub(self.issuance.issued_at) > 300
            || issuer.valid_from > self.issuance.issued_at
            || now > issuer.valid_until
        {
            return Err("confidential issuance differs from its issuer cohort or validity".into());
        }
        let message = self.issuance.issuer_message()?;
        ed25519_dalek::VerifyingKey::from_bytes(&issuer.public_key)
            .map_err(|e| e.to_string())?
            .verify_strict(&message, &self.issuance.issuer_signature)
            .map_err(|e| e.to_string())?;
        zkfmi_crypto::backend::MlDsa65Verifier
            .verify(
                zkfmi_crypto::key::KeyPurpose::Attestation,
                &issuer.pq_public_key,
                &message,
                &self.issuance.issuer_pq_signature,
            )
            .map_err(|e| e.to_string())?;
        let k = key();
        RangeProof::from_bytes(&self.range_proof)
            .map_err(|e| e.to_string())?
            .verify_single(
                &BulletproofGens::new(usize::from(self.amount_bits), 1),
                &PedersenGens {
                    B: point(&self.identity.tag)?,
                    B_blinding: k.h,
                },
                &mut Self::transcript(&Self::range_context(
                    &self.issuance,
                    &self.identity,
                    self.amount_bits,
                )?),
                &point(&self.issuance.output.value_commitment)?.compress(),
                usize::from(self.amount_bits),
            )
            .map_err(|e| format!("confidential issuance range failed: {e}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferContext {
    pub before_root: [u8; 32],
    pub operation_id: [u8; 32],
    pub deadline: u64,
    pub amount_bits: u16,
    pub identity_statement: [u8; 32],
}

impl TransferContext {
    pub fn bytes(&self) -> Result<[u8; 32], String> {
        if [self.before_root, self.operation_id, self.identity_statement].contains(&ZERO)
            || !matches!(self.amount_bits, 8 | 16 | 32 | 64)
            || self.deadline == 0
            || self.deadline > crate::MAX_UNIX_TIME
        {
            return Err("confidential transfer context is incomplete".into());
        }
        digest(b"DEFMI:CONFIDENTIAL:TRANSFER-CONTEXT:v1", self)
    }
}

/// Full proof bytes accompany every public projection; a committee-attested
/// digest alone cannot enter the asset-confidential note set.
#[derive(Clone)]
pub struct ConfidentialTransfer {
    pub context: TransferContext,
    pub identity: AssetIdentity,
    pub spend: NoteSpend,
    pub spend_proof: Vec<u8>,
}

impl ConfidentialTransfer {
    pub fn statement(&self) -> Result<[u8; 32], String> {
        self.context.bytes()?;
        if self.context.identity_statement != self.identity.statement()?
            || self.spend_proof.len() > MAX_WIRE
            || self.spend_proof.is_empty()
            || self.spend.input_lock_id != ZERO
            || self.spend.outputs.iter().any(|n| n.lock_id != ZERO)
        {
            return Err(
                "ordinary confidential transfer has another identity or locked notes".into(),
            );
        }
        digest(
            b"DEFMI:CONFIDENTIAL:TRANSFER:v1",
            &(
                &self.context,
                &self.identity,
                self.spend.body()?,
                <[u8; 32]>::from(Sha256::digest(&self.spend_proof)),
            ),
        )
    }

    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        canonical_ring: &[NoteOutput],
        rng: &mut R,
    ) -> Result<(), String> {
        self.statement()?;
        verify_spend(
            &self.spend,
            &decode_spend_proof(&self.spend_proof)?,
            &self.identity,
            canonical_ring,
            usize::from(self.context.amount_bits),
            &self.context.bytes()?,
            rng,
        )
    }
}

#[derive(Clone)]
pub struct ConfidentialReservation {
    pub reservation: ApplicationNoteReservation,
    pub identity: AssetIdentity,
    pub value_link: ValueLink,
}

impl ConfidentialReservation {
    /// The private mandate already commits the asset identity, normalized
    /// amount and delegation. Bind the complete credit transition as well.
    pub fn spend_context(
        binding: &ApplicationReservationBinding,
        transition: &CreditFacilityTransition,
        identity: &AssetIdentity,
    ) -> Result<[u8; 32], String> {
        binding.validate()?;
        digest(
            b"DEFMI:CONFIDENTIAL:RESERVE-SPEND:v1",
            &(binding, transition.body()?, identity.statement()?),
        )
    }

    pub fn value_context(&self) -> Result<[u8; 32], String> {
        digest(
            b"DEFMI:CONFIDENTIAL:RESERVE-VALUE:v1",
            &(
                Self::spend_context(
                    &self.reservation.binding,
                    &self.reservation.transition,
                    &self.identity,
                )?,
                self.reservation.escrow.escrow_note_id,
                self.reservation.escrow.spend.body()?,
            ),
        )
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        if self.reservation.binding.asset_id != self.identity.commitment {
            return Err("confidential reserve names another asset identity".into());
        }
        digest(
            b"DEFMI:CONFIDENTIAL:RESERVATION:v1",
            &(
                self.reservation.body_with_confidential_value(true)?,
                &self.identity,
                &self.value_link,
            ),
        )
    }

    pub fn verify_public<R: RngCore + CryptoRng>(
        &self,
        canonical_ring: &[NoteOutput],
        rng: &mut R,
    ) -> Result<(), String> {
        self.statement()?;
        let r = &self.reservation;
        CreditFacilityRelationProof::from_bytes(&r.relation_proof)?.verify(&r.transition)?;
        verify_spend(
            &r.escrow.spend,
            &decode_spend_proof(&r.spend_proof)?,
            &self.identity,
            canonical_ring,
            usize::from(r.binding.scope.amount_bits),
            &Self::spend_context(&r.binding, &r.transition, &self.identity)?,
            rng,
        )?;
        let escrow = r
            .escrow
            .spend
            .outputs
            .iter()
            .find(|n| n.note_id == r.escrow.escrow_note_id)
            .ok_or("confidential reserve escrow is absent")?;
        self.value_link.verify(
            &point(&self.identity.tag)?,
            &key().g,
            &point(&escrow.value_commitment)?,
            &point(&r.binding.amount_commitment)?,
            &self.value_context()?,
        )
    }
}

/// Approval services use this constructor with their own DeKYX trust anchors.
/// A public proof does not replace private credential and mandate verification.
pub struct VerifiedConfidentialReservation(ConfidentialReservation);

impl VerifiedConfidentialReservation {
    pub fn verify<R: RngCore + CryptoRng>(
        reservation: ConfidentialReservation,
        mandate: &ApplicationReserveMandate,
        scope: &ApplicationReserveScope,
        identity: &ApplicationIdentityEvidence<'_>,
        canonical_ring: &[NoteOutput],
        now: u64,
        rng: &mut R,
    ) -> Result<Self, String> {
        use dekyx_core::{EligibilityProvider, SubjectKind};
        mandate.verify(scope, now)?;
        if mandate.binding()? != reservation.reservation.binding
            || identity.requirement.subject_kind != SubjectKind::LegalEntity
        {
            return Err("confidential reserve mandate or legal-entity requirement differs".into());
        }
        let verified = identity
            .verifier
            .verify_eligibility(
                identity.requirement,
                &mandate.identity_context(identity.requirement.scope_digest)?,
                identity.presentation,
                now,
            )
            .map_err(|e| e.to_string())?;
        if identity
            .presentation
            .credential
            .digest()
            .map_err(|e| e.to_string())?
            != mandate.credential_digest
            || verified.subject_line_id != mandate.entity_commitment
            || verified.valid_until < mandate.valid_until
        {
            return Err("confidential reserve credential belongs to another entity".into());
        }
        reservation.verify_public(canonical_ring, rng)?;
        Ok(Self(reservation))
    }

    pub fn reservation(&self) -> &ConfidentialReservation {
        &self.0
    }
}
