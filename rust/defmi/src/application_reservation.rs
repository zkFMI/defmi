//! Application-neutral, participant-authorized anonymous-note reservations.
//!
//! An order may be a liquidity taker now and a maker later. Its reservation
//! therefore does not invent an RFQ ticket or register a dealer policy. The
//! participant signs a bounded application mandate before matching, proves
//! note ownership and facility solvency, and delegates only that exact hold.
//! The existing note-spend and credit proof implementations are reused.

use crate::facility::{
    CreditFacilityRelationProof, CreditFacilityTransition, CreditTransitionKind, ZERO,
};
use crate::note_chain::NoteReservationEscrow;
use crate::notes::{decode_spend_proof, encode_spend_proof, Note, NoteLedger, SpendProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use dekyx_core::{
    AnonymousPresentation, DeKyxVerifier, EligibilityProvider, EligibilityRequirement,
    PresentationContext, SubjectKind,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zkfmi_crypto::{
    hybrid::signature::HybridVerifier,
    key::KeyPurpose,
    suite::{Suite, SuiteId},
    traits::{Signer, Verifier},
};

const MANDATE_DOMAIN: &[u8] = b"DEFMI:APPLICATION:RESERVE-MANDATE:v2";
const IDENTITY_DOMAIN: &[u8] = b"DEFMI:APPLICATION:RESERVE-IDENTITY:v1";
const SPEND_DOMAIN: &[u8] = b"DEFMI:APPLICATION:RESERVE-SPEND:v1";
const DELEGATION_DOMAIN: &[u8] = b"DEFMI:APPLICATION:RESERVE-DELEGATION:v1";
const RESERVATION_DOMAIN: &[u8] = b"DEFMI:APPLICATION:NOTE-RESERVATION:v1";
const MAX_UNIX_TIME: u64 = 253_402_300_799;

/// Deployment configuration, never learned from an incoming mandate. The
/// committee digest names the key authorized for the later application proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReserveScope {
    pub application_binding: [u8; 32],
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub committee_key_digest: [u8; 32],
    pub pq_committee_digest: [u8; 32],
    pub committee_epoch: u64,
    pub amount_bits: u16,
}

impl ApplicationReserveScope {
    pub fn validate(&self) -> Result<(), String> {
        if self.committee_epoch == 0
            || !matches!(self.amount_bits, 8 | 16 | 32 | 64)
            || [
                self.application_binding,
                self.venue_id,
                self.defmi_id,
                self.committee_key_digest,
                self.pq_committee_digest,
            ]
            .contains(&ZERO)
        {
            return Err("application reserve scope is incomplete".into());
        }
        Ok(())
    }

    pub fn key(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        Ok(Sha256::new()
            .chain_update(b"DEFMI:APPLICATION:RESERVE-SCOPE:v1")
            .chain_update(self.application_binding)
            .chain_update(self.venue_id)
            .chain_update(self.defmi_id)
            .chain_update(self.committee_epoch.to_be_bytes())
            .finalize()
            .into())
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(b"DEFMI:APPLICATION:HYBRID-RESERVE-SCOPE:v2")
            .chain_update(self.key()?)
            .chain_update(self.committee_key_digest)
            .chain_update(self.pq_committee_digest)
            .chain_update(self.amount_bits.to_be_bytes())
            .finalize()
            .into())
    }

    /// Both key sets are fixed before the participant authorizes a reserve.
    pub fn verify_committee(
        &self,
        classical: &[u8],
        policy: &zkpi::QuorumPolicy,
    ) -> Result<zkpi::frost::keys::PublicKeyPackage, String> {
        self.validate()?;
        if classical.len() > 64 * 1024
            || <[u8; 32]>::from(Sha256::digest(classical)) != self.committee_key_digest
            || policy.digest().map_err(|error| error.to_string())? != self.pq_committee_digest
            || policy.epoch != self.committee_epoch
            || policy.threshold != 3
            || policy.members.len() != 7
        {
            return Err(
                "application committee differs from its pre-authorized classical/PQ keys".into(),
            );
        }
        let public = zkpi::frost::keys::PublicKeyPackage::deserialize(classical)
            .map_err(|_| "application committee key is malformed")?;
        if public
            .serialize()
            .map_err(|_| "application committee cannot be serialized")?
            != classical
        {
            return Err("application committee is not canonical".into());
        }
        zkpi::validate_settlement_committee(policy, &public).map_err(str::to_string)?;
        Ok(public)
    }
}

/// Private pre-trade authorization. Do not send this to the market's public
/// coordinator: the asset/facility references can identify the funding leg.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReserveMandate {
    pub version: u16,
    pub scope: ApplicationReserveScope,
    /// Salted application request binding; never the public order hash alone.
    pub request_commitment: [u8; 32],
    pub facility_id: [u8; 32],
    pub hold_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub participant_handle: [u8; 32],
    pub entity_commitment: [u8; 32],
    /// Signed credential digest, known before the mandate is signed. Never
    /// hash the later presentation here: that would create a circular binding.
    pub credential_digest: [u8; 32],
    /// Application-defined hidden settlement condition (for OCLOB: side).
    /// Kept out of the public ledger because it also appears in the MPC VSS.
    pub settlement_terms_commitment: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
    pub participant_public: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ApplicationReserveMandate {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        self.scope.validate()?;
        if self.version != 2
            || self.valid_from == 0
            || self.valid_until < self.valid_from
            || self.valid_until > MAX_UNIX_TIME
            || self.signature.len() > 3373
            || self.participant_public.len() != 1984
        {
            return Err("application reserve mandate has an invalid lifetime or version".into());
        }
        let mut body = MANDATE_DOMAIN.to_vec();
        body.extend_from_slice(&self.version.to_be_bytes());
        for value in [
            self.scope.application_binding,
            self.scope.venue_id,
            self.scope.defmi_id,
            self.scope.committee_key_digest,
            self.request_commitment,
            self.facility_id,
            self.hold_id,
            self.asset_id,
            self.amount_commitment,
            self.participant_handle,
            self.entity_commitment,
            self.credential_digest,
            self.settlement_terms_commitment,
        ] {
            if value == ZERO {
                return Err("application reserve mandate has a zero binding".into());
            }
            body.extend_from_slice(&value);
        }
        body.extend_from_slice(&Suite::new(SuiteId::Ed25519MlDsa65).encode());
        body.extend_from_slice(&self.participant_public);
        for value in [
            self.amount_commitment,
            self.participant_handle,
            self.settlement_terms_commitment,
        ] {
            if CompressedRistretto(value).decompress().is_none() {
                return Err("application reserve mandate has an invalid point".into());
            }
        }
        for value in [
            self.scope.committee_epoch,
            self.valid_from,
            self.valid_until,
        ] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        body.extend_from_slice(&self.scope.amount_bits.to_be_bytes());
        Ok(body)
    }

    pub fn sign(mut self, key: &dyn Signer) -> Result<Self, String> {
        if key.suite() != Suite::new(SuiteId::Ed25519MlDsa65)
            || key.public_key() != self.participant_public
        {
            return Err("application reserve signer differs from its mandate".into());
        }
        self.signature = key
            .sign(KeyPurpose::SettlementInstruction, &self.unsigned()?)
            .map_err(|error| error.to_string())?;
        Ok(self)
    }

    pub fn verify(&self, scope: &ApplicationReserveScope, now: u64) -> Result<(), String> {
        if &self.scope != scope || now < self.valid_from || now > self.valid_until {
            return Err("application reserve scope or current lifetime differs".into());
        }
        HybridVerifier
            .verify(
                KeyPurpose::SettlementInstruction,
                &self.participant_public,
                &self.unsigned()?,
                &self.signature,
            )
            .map_err(|_| "application reserve signature is invalid".into())
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.verify(&self.scope, self.valid_from)?;
        Ok(Sha256::new()
            .chain_update(self.unsigned()?)
            .chain_update(&self.signature)
            .finalize()
            .into())
    }

    /// Sign the credential-bound mandate first, then create the DeKYX proof
    /// for this exact action. The deployment supplies the eligibility scope.
    pub fn identity_context(
        &self,
        identity_scope: [u8; 32],
    ) -> Result<PresentationContext, String> {
        let context = PresentationContext {
            scope_digest: identity_scope,
            audience_digest: self.scope.statement()?,
            action_digest: Sha256::digest(IDENTITY_DOMAIN).into(),
            request_digest: self.digest()?,
            challenge_nonce: self.hold_id,
            valid_until: self.valid_until,
        };
        context.digest().map_err(|error| error.to_string())?;
        Ok(context)
    }

    pub fn spend_context(&self) -> Result<Vec<u8>, String> {
        Ok([SPEND_DOMAIN, self.digest()?.as_slice()].concat())
    }

    pub fn delegation_digest(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(DELEGATION_DOMAIN)
            .chain_update(self.digest()?)
            .finalize()
            .into())
    }

    pub fn binding(&self) -> Result<ApplicationReservationBinding, String> {
        Ok(ApplicationReservationBinding {
            scope: self.scope.clone(),
            request_commitment: self.request_commitment,
            facility_id: self.facility_id,
            hold_id: self.hold_id,
            asset_id: self.asset_id,
            amount_commitment: self.amount_commitment,
            entity_commitment: self.entity_commitment,
            mandate_digest: self.digest()?,
            delegation_digest: self.delegation_digest()?,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        })
    }
}

/// Only this projection is written to the public ledger. In particular,
/// publishing the participant handle or the mandate signing key would permit
/// a direct equality lookup from an MPC manifest to its funding asset.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReservationBinding {
    pub scope: ApplicationReserveScope,
    pub request_commitment: [u8; 32],
    pub facility_id: [u8; 32],
    pub hold_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount_commitment: [u8; 32],
    pub entity_commitment: [u8; 32],
    pub mandate_digest: [u8; 32],
    pub delegation_digest: [u8; 32],
    pub valid_from: u64,
    pub valid_until: u64,
}

impl ApplicationReservationBinding {
    pub fn validate(&self) -> Result<(), String> {
        self.scope.validate()?;
        if [
            self.request_commitment,
            self.facility_id,
            self.hold_id,
            self.asset_id,
            self.amount_commitment,
            self.entity_commitment,
            self.mandate_digest,
            self.delegation_digest,
        ]
        .contains(&ZERO)
            || self.valid_from == 0
            || self.valid_until < self.valid_from
            || self.valid_until > MAX_UNIX_TIME
            || CompressedRistretto(self.amount_commitment)
                .decompress()
                .is_none()
            || self.delegation_digest
                != <[u8; 32]>::from(
                    Sha256::new()
                        .chain_update(DELEGATION_DOMAIN)
                        .chain_update(self.mandate_digest)
                        .finalize(),
                )
        {
            return Err("application reservation binding is malformed".into());
        }
        Ok(())
    }
}

/// Consensus projection, after an approval service has verified the full
/// participant proof. It contains no quantity, price or commitment opening.
/// The VM must still check its current facility state and unspent note ring;
/// a successful local verification is not canonical finality.
#[derive(Clone)]
pub struct ApplicationNoteReservation {
    pub binding: ApplicationReservationBinding,
    pub transition: CreditFacilityTransition,
    pub escrow: NoteReservationEscrow,
    pub relation_proof: Vec<u8>,
    pub spend_proof: Vec<u8>,
}

impl ApplicationNoteReservation {
    pub fn body(&self) -> Result<Value, String> {
        self.body_with_confidential_value(false)
    }

    // Only the confidential wrapper may use this shape. It separately proves
    // equality of the tagged escrow value and the normalized credit amount.
    pub(crate) fn body_with_confidential_value(&self, confidential: bool) -> Result<Value, String> {
        let mandate = &self.binding;
        mandate.validate()?;
        if self.relation_proof.is_empty()
            || self.relation_proof.len() > 2 * 1024 * 1024 + 16
            || self.spend_proof.is_empty()
            || self.spend_proof.len() > 2 * 1024 * 1024
        {
            return Err("application reservation proof exceeds its wire bound".into());
        }
        self.transition.body()?;
        if self.transition.kind != CreditTransitionKind::Hold
            || self.transition.facility_id != mandate.facility_id
            || self.transition.hold_id != mandate.hold_id
            || self.transition.query_commitment != mandate.request_commitment
            || self.transition.amount_commitment != mandate.amount_commitment
            || self.transition.expires_at != mandate.valid_until
            || self.escrow.spend.asset_id != mandate.asset_id
            || self.escrow.spend.input_lock_id != ZERO
            || self.escrow.delegation_digest != mandate.delegation_digest
        {
            return Err("application note reservation differs from its signed mandate".into());
        }
        let locked = self
            .escrow
            .spend
            .outputs
            .iter()
            .filter(|note| note.lock_id == mandate.hold_id)
            .collect::<Vec<_>>();
        if locked.len() != 1
            || locked[0].note_id != self.escrow.escrow_note_id
            || (!confidential && locked[0].value_commitment != mandate.amount_commitment)
            || self
                .escrow
                .spend
                .outputs
                .iter()
                .any(|note| note.lock_id != ZERO && note.lock_id != mandate.hold_id)
        {
            return Err("application reservation does not create exactly its signed escrow".into());
        }
        Ok(json!({
            "binding": mandate,
            "transition": self.transition.body()?,
            "escrow_note_id": hex::encode(self.escrow.escrow_note_id),
            "delegation_digest": hex::encode(self.escrow.delegation_digest),
            "spend": self.escrow.spend.body()?,
            "relation_proof_sha256": hex::encode(Sha256::digest(&self.relation_proof)),
            "spend_proof_sha256": hex::encode(Sha256::digest(&self.spend_proof)),
        }))
    }

    pub fn statement(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(RESERVATION_DOMAIN)
            .chain_update(serde_json::to_vec(&self.body()?).map_err(|error| error.to_string())?)
            .finalize()
            .into())
    }

    /// Independent DeFMI validators reconstruct `ledger` from their own
    /// canonical notes, not from participant-supplied ring members. Both full
    /// proofs are verified, including ownership, no overspend and credit
    /// conservation. KYX/mandate approval remains a separate private boundary.
    pub fn verify_public_proofs<R: RngCore + CryptoRng>(
        &self,
        ledger: &NoteLedger,
        ring: &[usize],
        ring_locks: &[[u8; 32]],
        rng: &mut R,
    ) -> Result<(), String> {
        self.body()?;
        let key = zkfmi_zk::pedersen::Pedersen::new(b"qomm:defmi:v1");
        if ledger.bits != usize::from(self.binding.scope.amount_bits)
            || ledger.key.g != key.g
            || ledger.key.h != key.h
        {
            return Err("application note verifier has different commitment parameters".into());
        }
        CreditFacilityRelationProof::from_bytes(&self.relation_proof)?.verify(&self.transition)?;
        let proof = decode_spend_proof(&self.spend_proof)?;
        let notes = self
            .escrow
            .spend
            .outputs
            .iter()
            .map(|output| output.to_note())
            .collect::<Result<Vec<_>, _>>()?;
        let output_locks = self
            .escrow
            .spend
            .outputs
            .iter()
            .map(|output| output.lock_id)
            .collect::<Vec<_>>();
        let context = [SPEND_DOMAIN, self.binding.mandate_digest.as_slice()].concat();
        let verified = NoteReservationEscrow::from_verified(
            ledger,
            ring,
            &proof,
            &notes,
            self.binding.asset_id,
            ring_locks,
            &output_locks,
            &self.transition,
            self.binding.delegation_digest,
            &context,
            rng,
        )?;
        if verified != self.escrow {
            return Err(
                "application escrow differs from the independently verified note spend".into(),
            );
        }
        Ok(())
    }
}

/// Constructible only after the actual KYX, note ownership, range and facility
/// conservation proofs pass. Remote approval services must call this verifier,
/// not deserialize a caller's claimed verification result.
pub struct VerifiedApplicationNoteReservation(ApplicationNoteReservation);

/// The issuer registry, revocation list and eligibility requirement are
/// operator-configured trust anchors, not fields supplied by the participant.
/// DeKYX owns all credential and anonymous-presentation verification.
pub struct ApplicationIdentityEvidence<'a> {
    pub verifier: &'a DeKyxVerifier<'a>,
    pub requirement: &'a EligibilityRequirement,
    pub presentation: &'a AnonymousPresentation,
}

impl VerifiedApplicationNoteReservation {
    #[allow(clippy::too_many_arguments)]
    pub fn verify<R: RngCore + CryptoRng>(
        mandate: ApplicationReserveMandate,
        transition: CreditFacilityTransition,
        relation: &CreditFacilityRelationProof,
        scope: &ApplicationReserveScope,
        identity: &ApplicationIdentityEvidence<'_>,
        ledger: &NoteLedger,
        ring: &[usize],
        proof: &SpendProof,
        notes: &[Note],
        ring_locks: &[[u8; 32]],
        output_locks: &[[u8; 32]],
        now: u64,
        rng: &mut R,
    ) -> Result<Self, String> {
        mandate.verify(scope, now)?;
        let key = zkfmi_zk::pedersen::Pedersen::new(b"qomm:defmi:v1");
        if ledger.bits != usize::from(scope.amount_bits)
            || ledger.key.g != key.g
            || ledger.key.h != key.h
        {
            return Err("application reserve amount range differs from its deployment".into());
        }
        if identity.requirement.subject_kind != SubjectKind::LegalEntity {
            return Err("application reservation requires a legal-entity credential".into());
        }
        let identity_context = mandate.identity_context(identity.requirement.scope_digest)?;
        let verified_identity = identity
            .verifier
            .verify_eligibility(
                identity.requirement,
                &identity_context,
                identity.presentation,
                now,
            )
            .map_err(|error| format!("application reserve identity proof failed: {error}"))?;
        if identity
            .presentation
            .credential
            .digest()
            .map_err(|error| error.to_string())?
            != mandate.credential_digest
            || verified_identity.subject_line_id != mandate.entity_commitment
            || verified_identity.valid_until < mandate.valid_until
        {
            return Err("application reserve identity belongs to another entity".into());
        }
        relation.verify(&transition)?;
        let escrow = NoteReservationEscrow::from_verified(
            ledger,
            ring,
            proof,
            notes,
            mandate.asset_id,
            ring_locks,
            output_locks,
            &transition,
            mandate.delegation_digest()?,
            &mandate.spend_context()?,
            rng,
        )?;
        let reservation = ApplicationNoteReservation {
            binding: mandate.binding()?,
            transition,
            escrow,
            relation_proof: relation.to_bytes()?,
            spend_proof: encode_spend_proof(proof)?,
        };
        reservation.body()?;
        Ok(Self(reservation))
    }

    pub fn reservation(&self) -> &ApplicationNoteReservation {
        &self.0
    }
}
