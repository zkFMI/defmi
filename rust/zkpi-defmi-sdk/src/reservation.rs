//! Application-neutral proof that a DeFMI reservation already exists.
//!
//! The full permit is confidential settlement material: its asset and note
//! references may reveal the order side through canonical ledger records.
//! Each matching node receives only a [`crate::admission::ReservationAdmission`]
//! and a share of the key protecting the full permit. The settlement service
//! opens the permit only after threshold authorization of the matched order.

use crate::application::ApplicationManifest;
use crate::{SdkError, SdkResult};
use curve25519_dalek::ristretto::CompressedRistretto;
use qomm_defmi::application_reservation::{ApplicationReserveMandate, ApplicationReserveScope};
use qomm_defmi::avalanche::{AvalancheClient, CanonicalCreditHold, CanonicalNoteReservation};
use qomm_defmi::facility::{
    CreditFacilityTransition, CreditTransitionKind, ReservationAuthorization,
    ReservationRole as DefmiReservationRole,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkfmi_crypto::{
    hybrid::signature::{HybridSigner, HybridVerifier},
    key::KeyPurpose,
    traits::{Signer, Verifier},
};

const PERMIT_DOMAIN: &[u8] = b"ZKPI:DEFMI:APPLICATION-RESERVATION-PERMIT:v3";
const PERMIT_DIGEST_DOMAIN: &[u8] = b"ZKPI:DEFMI:APPLICATION-RESERVATION-DIGEST:v2";
const PERMIT_VERSION: u16 = 3;
const MAX_WIRE_BYTES: usize = 32 * 1024;
const MAX_UNIX_TIME: u64 = 253_402_300_799;
const ZERO: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationRole {
    /// Inventory or cash committed by a standing liquidity provider.
    Maker,
    /// Inventory or cash committed when an arriving order is submitted.
    Taker,
    /// A role-neutral application hold. A CLOB order may take liquidity on
    /// arrival and supply its remainder later, without becoming an RFQ.
    Application,
}

impl ReservationRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Maker => 1,
            Self::Taker => 2,
            Self::Application => 3,
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
    pub signer_public: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Private request to an authorized DeFMI permit issuer. The issuer obtains
/// canonical evidence from its own trusted Avalanche client; the caller cannot
/// supply a purported readback. The authorization must bind this exact order
/// commitment, and the participant proves the commitment opening to the MPC.
#[derive(Clone, Copy)]
pub struct ReservationPermitIssue<'a> {
    pub application: &'a ApplicationManifest,
    pub role: ReservationRole,
    pub venue_id: [u8; 32],
    pub defmi_id: [u8; 32],
    pub order_commitment: [u8; 32],
    /// Fresh wallet secret used only at the private issuance boundary. The
    /// ledger must not publish the application's order commitment verbatim.
    pub order_authorization_salt: [u8; 32],
    pub participant_handle: [u8; 32],
    pub side_commitment: [u8; 32],
    pub transition: &'a CreditFacilityTransition,
    pub authorization: &'a ReservationAuthorization,
    pub valid_until: u64,
    pub observed_at: u64,
}

#[derive(Clone, Copy)]
pub struct ApplicationReservationPermitIssue<'a> {
    pub application: &'a ApplicationManifest,
    pub scope: &'a ApplicationReserveScope,
    pub mandate: &'a ApplicationReserveMandate,
    pub order_commitment: [u8; 32],
    pub order_authorization_salt: [u8; 32],
    pub observed_at: u64,
}

impl ReservationPermit {
    /// Issue only after the role-neutral note reserve is finalized on the
    /// configured DeFMI deployment. The private mandate is checked against its
    /// exact canonical digest, never inserted into an RPC transaction itself.
    pub fn issue_from_application_reservation<C: AvalancheClient + ?Sized>(
        client: &C,
        input: ApplicationReservationPermitIssue<'_>,
        signer: &HybridSigner,
    ) -> SdkResult<Self> {
        let ApplicationReservationPermitIssue {
            application,
            scope,
            mandate,
            order_commitment,
            order_authorization_salt,
            observed_at,
        } = input;
        mandate.verify(scope, observed_at).map_err(invalid)?;
        let application_binding = application.digest()?;
        if scope.application_binding != application_binding
            || mandate.request_commitment
                != order_authorization_commitment(order_commitment, order_authorization_salt)?
        {
            return Err(invalid(
                "application reserve belongs to another request or application",
            ));
        }
        let before = client.state_root().map_err(SdkError::InvalidFinality)?;
        let canonical = client
            .application_reservation_snapshot(mandate.hold_id)
            .map_err(SdkError::InvalidFinality)?;
        let hold = client
            .credit_hold_snapshot(mandate.hold_id)
            .map_err(SdkError::InvalidFinality)?;
        let after = client.state_root().map_err(SdkError::InvalidFinality)?;
        if before == ZERO
            || before != after
            || canonical.state_root != before
            || hold.state_root != before
        {
            return Err(invalid(
                "application reservation readbacks do not share a stable root",
            ));
        }
        if canonical.binding != mandate.binding().map_err(invalid)?
            || canonical.sequence != 0
            || canonical.remaining_commitment != mandate.amount_commitment
            || canonical.head_receipt != canonical.reserve_receipt_digest
            || canonical.remaining_opening.is_some()
            || canonical.accepted_height == 0
            || canonical.status != "active"
            || canonical.settlement_digest != ZERO
            || canonical.escrow_note_id == ZERO
            || canonical.proof_digest == ZERO
            || canonical.reserve_receipt_digest == ZERO
            || hold.hold_id != mandate.hold_id
            || hold.facility_id != mandate.facility_id
            || hold.query_commitment != mandate.request_commitment
            || hold.amount_commitment != mandate.amount_commitment
            || hold.expires_at != mandate.valid_until
            || hold.status != "active"
            || hold.settlement_digest != ZERO
            || hold.created_sequence == 0
            || hold.created_sequence != hold.updated_sequence
        {
            return Err(invalid(
                "application reservation is not the untouched canonical hold for this mandate",
            ));
        }
        Self {
            version: PERMIT_VERSION,
            role: ReservationRole::Application,
            application_binding,
            venue_id: scope.venue_id,
            defmi_id: scope.defmi_id,
            canonical_state_root: before,
            accepted_height: canonical.accepted_height,
            order_commitment,
            participant_handle: mandate.participant_handle,
            entity_commitment: mandate.entity_commitment,
            reservation_id: mandate.hold_id,
            facility_id: mandate.facility_id,
            asset_id: mandate.asset_id,
            amount_commitment: mandate.amount_commitment,
            escrow_note_id: canonical.escrow_note_id,
            delegation_digest: canonical.binding.delegation_digest,
            side_commitment: mandate.settlement_terms_commitment,
            authority_digest: canonical.binding.mandate_digest,
            reserve_receipt_digest: canonical.reserve_receipt_digest,
            reservation_sequence: hold.created_sequence,
            valid_until: mandate.valid_until,
            signer_public: signer.public_key(),
            signature: Vec::new(),
        }
        .sign(signer)
    }

    /// Read an active anonymous-note reservation and credit hold at one stable
    /// canonical root before signing an application permit. Any read error or
    /// concurrent state change fails closed; callers can retry the whole read.
    ///
    /// `client` must be configured by the issuer, not selected by a requesting
    /// participant. The permit is an issuer attestation to a canonical readback,
    /// not a consensus proof or a substitute for checking the live hold when
    /// settling. No owner account or post-match owner signature is required.
    pub fn issue_from_avalanche<C: AvalancheClient + ?Sized>(
        client: &C,
        input: ReservationPermitIssue<'_>,
        signer: &HybridSigner,
    ) -> SdkResult<Self> {
        let before_root = client.state_root().map_err(SdkError::InvalidFinality)?;
        let canonical = client
            .note_reservation_snapshot(input.transition.hold_id)
            .map_err(SdkError::InvalidFinality)?;
        let hold = client
            .credit_hold_snapshot(input.transition.hold_id)
            .map_err(SdkError::InvalidFinality)?;
        let after_root = client.state_root().map_err(SdkError::InvalidFinality)?;
        if before_root == ZERO
            || before_root != after_root
            || canonical.state_root != before_root
            || hold.state_root != before_root
        {
            return Err(SdkError::InvalidFinality(
                "reservation reads do not share one stable canonical state root".into(),
            ));
        }
        Self::issue_from_canonical_note(input, &canonical, &hold, signer)
    }

    fn issue_from_canonical_note(
        input: ReservationPermitIssue<'_>,
        canonical: &CanonicalNoteReservation,
        hold: &CanonicalCreditHold,
        signer: &HybridSigner,
    ) -> SdkResult<Self> {
        let ReservationPermitIssue {
            application,
            role,
            venue_id,
            defmi_id,
            order_commitment,
            order_authorization_salt,
            participant_handle,
            side_commitment,
            transition,
            authorization,
            valid_until,
            observed_at,
        } = input;

        let expected_role = match role {
            ReservationRole::Maker => DefmiReservationRole::Maker,
            ReservationRole::Taker => DefmiReservationRole::Taker,
            ReservationRole::Application => {
                return Err(invalid(
                    "application reservations must use their dedicated canonical issuer",
                ))
            }
        };
        if authorization.role != expected_role {
            return Err(invalid(
                "reservation permit role does not match the DeFMI authorization",
            ));
        }
        if transition.kind != CreditTransitionKind::Hold
            || canonical.status != "active"
            || canonical.settlement_digest != ZERO
        {
            return Err(invalid(
                "reservation permit requires an active, unconsumed canonical hold",
            ));
        }
        if canonical.accepted_height == 0
            || canonical.state_root == ZERO
            || canonical.proof_digest == ZERO
            || canonical.escrow_note_id == ZERO
            || canonical.delegation_digest == ZERO
        {
            return Err(invalid(
                "canonical note reservation lacks accepted readback evidence",
            ));
        }
        if canonical.hold_id != transition.hold_id
            || canonical.amount_commitment != transition.amount_commitment
            || canonical.asset_id != authorization.asset_id
        {
            return Err(invalid(
                "canonical note reservation does not match its transition or authorization",
            ));
        }
        let reserve_receipt_digest = authorization.statement(transition).map_err(|error| {
            invalid(format!(
                "DeFMI reservation authorization is invalid: {error}"
            ))
        })?;
        if canonical.reserve_receipt_digest != reserve_receipt_digest {
            return Err(invalid(
                "canonical note reservation names another reserve receipt",
            ));
        }
        if observed_at == 0
            || valid_until < observed_at
            || valid_until > transition.expires_at
            || valid_until > MAX_UNIX_TIME
        {
            return Err(invalid(
                "reservation permit validity is outside the canonical hold lifetime",
            ));
        }
        let reservation_sequence = transition
            .before_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("reservation sequence overflows"))?;
        let authority = order_authorization_commitment(order_commitment, order_authorization_salt)?;
        if transition.query_commitment != authority
            || hold.hold_id != transition.hold_id
            || hold.facility_id != transition.facility_id
            || hold.query_commitment != authority
            || hold.amount_commitment != transition.amount_commitment
            || hold.expires_at != transition.expires_at
            || hold.status != "active"
            || hold.settlement_digest != ZERO
            || hold.created_sequence != reservation_sequence
            || hold.updated_sequence != reservation_sequence
        {
            return Err(invalid(
                "canonical credit hold is not the untouched reservation for this exact order",
            ));
        }

        Self {
            version: PERMIT_VERSION,
            role,
            application_binding: application.digest()?,
            venue_id,
            defmi_id,
            canonical_state_root: canonical.state_root,
            accepted_height: canonical.accepted_height,
            order_commitment,
            participant_handle,
            entity_commitment: authorization.entity_commitment,
            reservation_id: transition.hold_id,
            facility_id: transition.facility_id,
            asset_id: authorization.asset_id,
            amount_commitment: transition.amount_commitment,
            escrow_note_id: canonical.escrow_note_id,
            delegation_digest: canonical.delegation_digest,
            side_commitment,
            authority_digest: authorization.authorization_digest,
            reserve_receipt_digest,
            reservation_sequence,
            valid_until,
            signer_public: signer.public_key(),
            signature: Vec::new(),
        }
        .sign(signer)
    }

    pub fn validate(&self) -> SdkResult<()> {
        if self.version != PERMIT_VERSION
            || self.accepted_height == 0
            || self.valid_until == 0
            || self.valid_until > MAX_UNIX_TIME
            || self.signature.len() > 3373
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
        if self.signer_public.len() != 1984 {
            return Err(invalid("reservation permit requires a hybrid signer"));
        }
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

    pub fn sign(mut self, key: &HybridSigner) -> SdkResult<Self> {
        if self.signer_public != key.public_key() || !self.signature.is_empty() {
            return Err(invalid(
                "reservation permit signing key or initial signature is invalid",
            ));
        }
        self.signature = key
            .sign(KeyPurpose::SettlementInstruction, &self.unsigned_body()?)
            .map_err(|_| invalid("reservation permit signing failed"))?;
        Ok(self)
    }

    pub fn verify(
        &self,
        expected_application: [u8; 32],
        expected_defmi: [u8; 32],
        trusted_signer: &[u8],
        now: u64,
    ) -> SdkResult<()> {
        if self.application_binding != expected_application
            || self.defmi_id != expected_defmi
            || self.signer_public != trusted_signer
            || now > self.valid_until
            || self.signature.len() != 3373
        {
            return Err(invalid(
                "reservation permit application, DeFMI, signer, time, or signature is invalid",
            ));
        }
        HybridVerifier
            .verify(
                KeyPurpose::SettlementInstruction,
                trusted_signer,
                &self.unsigned_body()?,
                &self.signature,
            )
            .map_err(|_| invalid("reservation permit signature does not verify"))
    }

    pub fn digest(&self) -> SdkResult<[u8; 32]> {
        if self.signature.len() != 3373 {
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

/// Private wallet binding used as the DeFMI authorization/query commitment.
/// The random 32-byte salt is never sent to matching nodes or the coordinator.
pub fn order_authorization_commitment(order: [u8; 32], salt: [u8; 32]) -> SdkResult<[u8; 32]> {
    if order == ZERO || salt == ZERO {
        return Err(invalid(
            "order authorization needs an order and a fresh secret salt",
        ));
    }
    Ok(Sha256::new()
        .chain_update(b"ZKPI:DEFMI:PRIVATE-ORDER-AUTHORIZATION:v1")
        .chain_update(order)
        .chain_update(salt)
        .finalize()
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::oclob_manifest_v1;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use qomm_defmi::facility::{CreditFacilityTransition, ReservationAuthorization};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn signed() -> (ReservationPermit, std::sync::Arc<HybridSigner>) {
        let signer = zkfmi_crypto::test_support::hybrid_signer(&id(19));
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
            signer_public: signer.public_key(),
            signature: Vec::new(),
        }
        .sign(&signer)
        .unwrap();
        (permit, signer)
    }

    #[test]
    fn signed_private_permit_round_trips() {
        let (permit, signer) = signed();
        let application = oclob_manifest_v1().digest().unwrap();
        permit
            .verify(application, id(2), &signer.public_key(), 1_000)
            .unwrap();
        let wire = permit.encode().unwrap();
        let decoded = ReservationPermit::decode(&wire).unwrap();
        assert_eq!(decoded, permit);
        assert_eq!(decoded.digest().unwrap(), permit.digest().unwrap());
    }

    #[test]
    fn admission_omits_ledger_references_and_tags_reissued_holds() {
        use crate::admission::ReservationAdmission;
        let (permit, signer) = signed();
        let reblinding = Scalar::from(91_u64);
        let admission =
            ReservationAdmission::from_permit(&permit, &reblinding, &signer, &[91; 32]).unwrap();
        admission
            .verify(
                permit.application_binding,
                permit.defmi_id,
                &signer.public_key(),
                1_000,
            )
            .unwrap();
        admission.verify_authority(&permit, &reblinding).unwrap();
        assert_ne!(admission.amount_commitment, permit.amount_commitment);
        assert!(admission
            .verify_authority(&permit, &Scalar::from(92_u64))
            .is_err());
        assert!(
            ReservationAdmission::from_permit(&permit, &Scalar::ZERO, &signer, &[91; 32]).is_err()
        );
        let wire = admission.encode().unwrap();
        assert_eq!(ReservationAdmission::decode(&wire).unwrap(), admission);
        let object: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        for forbidden in [
            "role",
            "asset_id",
            "entity_commitment",
            "reservation_id",
            "facility_id",
            "escrow_note_id",
            "canonical_state_root",
            "accepted_height",
            "delegation_digest",
            "reserve_receipt_digest",
        ] {
            assert!(
                object.get(forbidden).is_none(),
                "admission disclosed {forbidden}"
            );
        }
        let mut reissued = permit.clone();
        reissued.canonical_state_root = id(75);
        reissued.accepted_height += 1;
        reissued.signature.clear();
        reissued = reissued.sign(&signer).unwrap();
        let reissued_admission =
            ReservationAdmission::from_permit(&reissued, &reblinding, &signer, &[91; 32]).unwrap();
        assert_ne!(
            admission.authority_commitment,
            reissued_admission.authority_commitment
        );
        assert_eq!(
            admission.reservation_nullifier,
            reissued_admission.reservation_nullifier
        );
        assert!(admission.verify_authority(&reissued, &reblinding).is_err());
        let mut other_hold = permit.clone();
        other_hold.reservation_id = id(76);
        other_hold.signature.clear();
        other_hold = other_hold.sign(&signer).unwrap();
        assert_ne!(
            admission.reservation_nullifier,
            ReservationAdmission::from_permit(&other_hold, &reblinding, &signer, &[91; 32])
                .unwrap()
                .reservation_nullifier
        );
        let mut tampered = admission.clone();
        tampered.authority_commitment = id(77);
        assert!(tampered
            .verify(
                permit.application_binding,
                permit.defmi_id,
                &signer.public_key(),
                1_000
            )
            .is_err());
        assert!(admission
            .verify(
                permit.application_binding,
                permit.defmi_id,
                &signer.public_key(),
                2_001
            )
            .is_err());
        assert!(ReservationAdmission::from_permit(
            &permit,
            &reblinding,
            &zkfmi_crypto::test_support::hybrid_signer(&id(78)),
            &[91; 32]
        )
        .is_err());
    }

    #[test]
    fn rejects_tampering_expiry_and_cross_application_replay() {
        let (permit, signer) = signed();
        let application = oclob_manifest_v1().digest().unwrap();
        assert!(permit
            .verify(application, id(2), &signer.public_key(), 2_001)
            .is_err());
        let mut tampered = permit.clone();
        tampered.reservation_id = id(99);
        assert!(tampered
            .verify(application, id(2), &signer.public_key(), 1_000)
            .is_err());
        assert!(permit
            .verify(id(88), id(2), &signer.public_key(), 1_000)
            .is_err());
    }

    #[test]
    fn reservation_evidence_rejects_either_signature_component_and_wrong_purpose() {
        let (permit, signer) = signed();
        let admission = crate::admission::ReservationAdmission::from_permit(
            &permit,
            &Scalar::from(91_u64),
            &signer,
            &[92; 32],
        )
        .unwrap();
        for index in [0, 64, 3372] {
            let mut altered = permit.clone();
            altered.signature[index] ^= 1;
            assert!(altered
                .verify(
                    permit.application_binding,
                    permit.defmi_id,
                    &signer.public_key(),
                    1000
                )
                .is_err());
            let mut altered = admission.clone();
            altered.signature[index] ^= 1;
            assert!(altered
                .verify(
                    permit.application_binding,
                    permit.defmi_id,
                    &signer.public_key(),
                    1000
                )
                .is_err());
        }
        let mut stripped = permit.clone();
        stripped.signature.truncate(64);
        assert!(stripped
            .verify(
                permit.application_binding,
                permit.defmi_id,
                &signer.public_key(),
                1000
            )
            .is_err());
        let mut wrong_purpose = permit.clone();
        wrong_purpose.signature = signer
            .sign(KeyPurpose::Order, &permit.unsigned_body().unwrap())
            .unwrap();
        assert!(wrong_purpose
            .verify(
                permit.application_binding,
                permit.defmi_id,
                &signer.public_key(),
                1000
            )
            .is_err());
        assert!(crate::admission::ReservationAdmission::from_permit(
            &permit,
            &Scalar::from(91_u64),
            &signer,
            &[0; 32]
        )
        .is_err());
    }

    fn canonical_issue_inputs() -> (
        CanonicalNoteReservation,
        CreditFacilityTransition,
        ReservationAuthorization,
    ) {
        let amount = (RISTRETTO_BASEPOINT_POINT * Scalar::from(23_u64))
            .compress()
            .to_bytes();
        let transition = CreditFacilityTransition {
            operation_id: id(31),
            facility_id: id(32),
            hold_id: id(33),
            kind: CreditTransitionKind::Hold,
            query_commitment: order_authorization_commitment(id(34), id(79)).unwrap(),
            amount_commitment: amount,
            consumed_commitment: ZERO,
            refund_commitment: ZERO,
            before_available_commitment: amount,
            after_available_commitment: amount,
            before_held_commitment: amount,
            after_held_commitment: amount,
            before_outstanding_commitment: amount,
            after_outstanding_commitment: amount,
            before_sequence: 7,
            expires_at: 4_000,
            settlement_digest: ZERO,
            relation_proof_digest: id(35),
        };
        let authorization = ReservationAuthorization {
            role: DefmiReservationRole::Taker,
            entity_commitment: id(36),
            asset_id: id(37),
            direction: 1,
            authorization_digest: transition.query_commitment,
            mandate_digest: id(38),
            typed_reserve_digest: id(39),
            reserve_nullifier: id(40),
            asset_link_proof_digest: id(41),
            limit_price_commitment: (RISTRETTO_BASEPOINT_POINT * Scalar::from(42_u64))
                .compress()
                .to_bytes(),
            escrow_digest: id(43),
            rfq_nullifier: id(44),
            policy_version: 0,
            admission_ticket_id: id(45),
            admission_slot: 1,
            admission_receipt_digest: id(46),
            admission_epoch: 1,
            admission_sequence: 1,
            admission_batch_id: id(47),
        };
        let canonical = CanonicalNoteReservation {
            state_root: id(48),
            accepted_height: 99,
            hold_id: transition.hold_id,
            escrow_note_id: id(49),
            asset_id: authorization.asset_id,
            amount_commitment: transition.amount_commitment,
            proof_digest: id(50),
            delegation_digest: id(51),
            reserve_receipt_digest: authorization.statement(&transition).unwrap(),
            status: "active".into(),
            settlement_digest: ZERO,
        };
        (canonical, transition, authorization)
    }

    // Unit-level readback fixture. Live validator acceptance is a separate gate.
    struct ReadbackClient {
        note: CanonicalNoteReservation,
        application: Option<qomm_defmi::avalanche::CanonicalApplicationReservation>,
        hold: CanonicalCreditHold,
        after_root: [u8; 32],
        reads: AtomicUsize,
        fail_note: bool,
    }

    impl ReadbackClient {
        fn new(note: &CanonicalNoteReservation, transition: &CreditFacilityTransition) -> Self {
            Self {
                note: note.clone(),
                application: None,
                hold: CanonicalCreditHold {
                    state_root: note.state_root,
                    hold_id: transition.hold_id,
                    facility_id: transition.facility_id,
                    query_commitment: transition.query_commitment,
                    amount_commitment: transition.amount_commitment,
                    expires_at: transition.expires_at,
                    status: "active".into(),
                    settlement_digest: ZERO,
                    created_sequence: transition.before_sequence + 1,
                    updated_sequence: transition.before_sequence + 1,
                },
                after_root: note.state_root,
                reads: AtomicUsize::new(0),
                fail_note: false,
            }
        }
    }

    impl AvalancheClient for ReadbackClient {
        fn application_reservation_snapshot(
            &self,
            hold_id: [u8; 32],
        ) -> Result<qomm_defmi::avalanche::CanonicalApplicationReservation, String> {
            self.application
                .as_ref()
                .filter(|reservation| !self.fail_note && reservation.binding.hold_id == hold_id)
                .cloned()
                .ok_or_else(|| "canonical application reservation is unavailable".into())
        }
        fn state_root(&self) -> Result<[u8; 32], String> {
            Ok(if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
                id(48)
            } else {
                self.after_root
            })
        }

        fn note_reservation_snapshot(
            &self,
            hold_id: [u8; 32],
        ) -> Result<CanonicalNoteReservation, String> {
            if self.fail_note || hold_id != id(33) {
                return Err("canonical reservation is unavailable".into());
            }
            Ok(self.note.clone())
        }

        fn credit_hold_snapshot(&self, hold_id: [u8; 32]) -> Result<CanonicalCreditHold, String> {
            if hold_id != id(33) {
                return Err("canonical hold is unavailable".into());
            }
            Ok(self.hold.clone())
        }

        fn issue_asset(
            &self,
            _: &qomm_defmi::facility::AssetDefinition,
            _: &qomm_defmi::facility::QuorumApproval,
            _: [u8; 32],
        ) -> Result<String, String> {
            panic!("permit issuance must not mutate the ledger")
        }

        fn issue_account(
            &self,
            _: &qomm_defmi::facility::AccountOpening,
            _: &qomm_defmi::facility::QuorumApproval,
            _: [u8; 32],
        ) -> Result<String, String> {
            panic!("permit issuance must not create an account")
        }

        fn issue_settlement(
            &self,
            _: &qomm_defmi::facility::SettlementOrder,
            _: &qomm_defmi::facility::QuorumApproval,
            _: [u8; 32],
        ) -> Result<String, String> {
            panic!("permit issuance must not settle a trade")
        }

        fn wait_accepted(
            &self,
            _: &str,
            _: std::time::Duration,
            _: std::time::Duration,
        ) -> Result<qomm_defmi::avalanche::AcceptedTransition, String> {
            panic!("permit issuance reads already accepted state")
        }
    }

    #[test]
    fn issues_application_permits_only_for_the_signed_finalized_note_hold() {
        use qomm_defmi::avalanche::CanonicalApplicationReservation;
        let (legacy, transition, _) = canonical_issue_inputs();
        let application = oclob_manifest_v1();
        let scope = ApplicationReserveScope {
            application_binding: application.digest().unwrap(),
            venue_id: id(55),
            defmi_id: id(56),
            committee_key_digest: id(57),
            pq_committee_digest: [231; 32],
            committee_epoch: 1,
            amount_bits: 32,
        };
        let participant = zkfmi_crypto::test_support::hybrid_signer(&id(58));
        let mandate = ApplicationReserveMandate {
            version: 2,
            scope: scope.clone(),
            request_commitment: transition.query_commitment,
            facility_id: transition.facility_id,
            hold_id: transition.hold_id,
            asset_id: legacy.asset_id,
            amount_commitment: legacy.amount_commitment,
            participant_handle: (RISTRETTO_BASEPOINT_POINT * Scalar::from(59_u64))
                .compress()
                .to_bytes(),
            entity_commitment: id(60),
            credential_digest: id(61),
            settlement_terms_commitment: (RISTRETTO_BASEPOINT_POINT * Scalar::from(62_u64))
                .compress()
                .to_bytes(),
            valid_from: 100,
            valid_until: transition.expires_at,
            participant_public: participant.public_key(),
            signature: vec![],
        }
        .sign(participant.as_ref())
        .unwrap();
        let canonical = CanonicalApplicationReservation {
            state_root: legacy.state_root,
            accepted_height: legacy.accepted_height,
            binding: mandate.binding().unwrap(),
            escrow_note_id: legacy.escrow_note_id,
            proof_digest: legacy.proof_digest,
            reserve_receipt_digest: legacy.reserve_receipt_digest,
            status: "active".into(),
            settlement_digest: ZERO,
            sequence: 0,
            remaining_commitment: mandate.amount_commitment,
            head_receipt: legacy.reserve_receipt_digest,
            remaining_opening: None,
        };
        let reader = || {
            let mut reader = ReadbackClient::new(&legacy, &transition);
            reader.application = Some(canonical.clone());
            reader
        };
        let signer = zkfmi_crypto::test_support::hybrid_signer(&id(63));
        let input = ApplicationReservationPermitIssue {
            application: &application,
            scope: &scope,
            mandate: &mandate,
            order_commitment: id(34),
            order_authorization_salt: id(79),
            observed_at: 200,
        };
        let issue = |reader: &ReadbackClient, input| {
            ReservationPermit::issue_from_application_reservation(reader, input, &signer)
        };
        let client = reader();
        let permit = issue(&client, input).unwrap();
        assert_eq!(client.reads.load(Ordering::SeqCst), 2);
        assert_eq!(permit.role, ReservationRole::Application);
        assert_eq!(permit.participant_handle, mandate.participant_handle);
        assert_eq!(permit.side_commitment, mandate.settlement_terms_commitment);
        assert_eq!(permit.authority_digest, mandate.digest().unwrap());
        assert_eq!(permit.escrow_note_id, canonical.escrow_note_id);
        assert_eq!(permit.reservation_sequence, transition.before_sequence + 1);
        permit
            .verify(
                application.digest().unwrap(),
                scope.defmi_id,
                &signer.public_key(),
                200,
            )
            .unwrap();
        assert_eq!(
            ReservationPermit::decode(&permit.encode().unwrap()).unwrap(),
            permit
        );
        let mutations: &[fn(&mut ReadbackClient)] = &[
            |r| r.application = None,
            |r| r.fail_note = true,
            |r| r.after_root = id(80),
            |r| r.hold.state_root = id(81),
            |r| r.application.as_mut().unwrap().state_root = id(82),
            |r| r.application.as_mut().unwrap().accepted_height = 0,
            |r| r.application.as_mut().unwrap().binding.entity_commitment = id(83),
            |r| r.application.as_mut().unwrap().binding.mandate_digest = id(84),
            |r| {
                r.application
                    .as_mut()
                    .unwrap()
                    .binding
                    .scope
                    .committee_epoch += 1
            },
            |r| r.application.as_mut().unwrap().binding.asset_id = id(85),
            |r| r.application.as_mut().unwrap().binding.delegation_digest = id(86),
            |r| r.application.as_mut().unwrap().binding.amount_commitment = id(87),
            |r| r.application.as_mut().unwrap().escrow_note_id = ZERO,
            |r| r.application.as_mut().unwrap().proof_digest = ZERO,
            |r| r.application.as_mut().unwrap().reserve_receipt_digest = ZERO,
            |r| r.application.as_mut().unwrap().status = "released".into(),
            |r| r.application.as_mut().unwrap().settlement_digest = id(88),
            |r| r.application.as_mut().unwrap().sequence = 1,
            |r| r.application.as_mut().unwrap().remaining_commitment = id(96),
            |r| r.application.as_mut().unwrap().head_receipt = id(97),
            |r| r.hold.status = "consumed".into(),
            |r| r.hold.settlement_digest = id(89),
            |r| r.hold.hold_id = id(90),
            |r| r.hold.facility_id = id(91),
            |r| r.hold.query_commitment = id(92),
            |r| r.hold.amount_commitment = id(93),
            |r| r.hold.expires_at += 1,
            |r| r.hold.created_sequence = 0,
            |r| r.hold.updated_sequence += 1,
        ];
        for (case, mutation) in mutations.iter().enumerate() {
            let mut client = reader();
            mutation(&mut client);
            assert!(
                issue(&client, input).is_err(),
                "accepted application readback mutation {case}"
            );
        }
        for input in [
            ApplicationReservationPermitIssue {
                order_commitment: id(94),
                ..input
            },
            ApplicationReservationPermitIssue {
                order_authorization_salt: id(95),
                ..input
            },
            ApplicationReservationPermitIssue {
                observed_at: 99,
                ..input
            },
            ApplicationReservationPermitIssue {
                observed_at: mandate.valid_until + 1,
                ..input
            },
        ] {
            assert!(issue(&reader(), input).is_err());
        }
        let mut forged = mandate.clone();
        forged.signature[0] ^= 1;
        assert!(issue(
            &reader(),
            ApplicationReservationPermitIssue {
                mandate: &forged,
                ..input
            }
        )
        .is_err());
    }

    #[test]
    fn issues_only_from_matching_active_canonical_note_reservation() {
        let signer = zkfmi_crypto::test_support::hybrid_signer(&id(52));
        let (canonical, transition, authorization) = canonical_issue_inputs();
        let application = oclob_manifest_v1();
        let participant_handle = (RISTRETTO_BASEPOINT_POINT * Scalar::from(53_u64))
            .compress()
            .to_bytes();
        let side_commitment = (RISTRETTO_BASEPOINT_POINT * Scalar::from(54_u64))
            .compress()
            .to_bytes();
        let input = ReservationPermitIssue {
            application: &application,
            role: ReservationRole::Taker,
            venue_id: id(55),
            defmi_id: id(56),
            order_commitment: id(34),
            order_authorization_salt: id(79),
            participant_handle,
            side_commitment,
            transition: &transition,
            authorization: &authorization,
            valid_until: 3_500,
            observed_at: 3_000,
        };
        let issue = |reader: &ReadbackClient, input| {
            ReservationPermit::issue_from_avalanche(reader, input, &signer)
        };
        let reader = ReadbackClient::new(&canonical, &transition);
        let permit = issue(&reader, input).expect("accepted readback should issue a permit");
        assert_ne!(permit.order_commitment, transition.query_commitment);
        assert_ne!(permit.order_commitment, permit.authority_digest);
        assert_eq!(reader.reads.load(Ordering::SeqCst), 2);
        permit
            .verify(
                oclob_manifest_v1().digest().unwrap(),
                id(56),
                &signer.public_key(),
                3_100,
            )
            .unwrap();
        assert_eq!(permit.escrow_note_id, canonical.escrow_note_id);
        assert_eq!(permit.delegation_digest, canonical.delegation_digest);
        assert_eq!(permit.reservation_sequence, 8);

        let mutations: &[fn(&mut ReadbackClient)] = &[
            |r| r.after_root = id(60),
            |r| r.note.state_root = id(61),
            |r| r.hold.state_root = id(62),
            |r| r.note.status = "consumed".into(),
            |r| r.note.settlement_digest = id(63),
            |r| r.note.reserve_receipt_digest = id(64),
            |r| r.note.amount_commitment = id(65),
            |r| r.note.asset_id = id(66),
            |r| r.note.hold_id = id(67),
            |r| r.note.escrow_note_id = ZERO,
            |r| r.note.delegation_digest = ZERO,
            |r| r.note.proof_digest = ZERO,
            |r| r.note.accepted_height = 0,
            |r| r.hold.facility_id = id(68),
            |r| r.hold.query_commitment = id(69),
            |r| r.hold.amount_commitment = id(70),
            |r| r.hold.created_sequence += 1,
            |r| r.hold.updated_sequence += 1,
            |r| r.hold.expires_at += 1,
            |r| r.hold.status = "released".into(),
            |r| r.hold.settlement_digest = id(71),
            |r| r.fail_note = true,
        ];
        for (case, mutation) in mutations.iter().enumerate() {
            let mut reader = ReadbackClient::new(&canonical, &transition);
            mutation(&mut reader);
            assert!(
                issue(&reader, input).is_err(),
                "accepted readback mutation {case}"
            );
        }
        for changed in [
            ReservationPermitIssue {
                order_commitment: id(72),
                ..input
            },
            ReservationPermitIssue {
                order_authorization_salt: id(73),
                ..input
            },
            ReservationPermitIssue {
                valid_until: transition.expires_at + 1,
                ..input
            },
            ReservationPermitIssue {
                valid_until: input.observed_at - 1,
                ..input
            },
            ReservationPermitIssue {
                observed_at: 0,
                ..input
            },
            ReservationPermitIssue {
                role: ReservationRole::Maker,
                ..input
            },
        ] {
            assert!(issue(&ReadbackClient::new(&canonical, &transition), changed).is_err());
        }
    }
}
