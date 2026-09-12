//! Fresh-network PQC note protocol, deliberately separate from Ristretto notes.
//!
//! This module defines wire objects, wallet openings and canonical identities.
//! Syntax validation is NOT a proof of ownership, membership, conservation,
//! correct recipient encryption, reservation authority or settlement validity.
//! No state-application API or caller-supplied `verified` flag is provided here.
//! In particular, anonymous spends expose nullifiers, never source note IDs or
//! membership indices. The new proved relation must retain that privacy boundary.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use zeroize::Zeroizing;
use zkfmi_crypto::{
    mode::{DeploymentCryptoPolicy, PqcMode},
    sealed::{SealedMessage, SealingPurpose, SealingWitness},
    traits::KemDecapsulator,
};

pub const VERSION: u16 = 1;
pub const MAX_NOTES_PER_TRANSITION: usize = 64;
pub const MAX_RESERVATIONS_PER_TRANSITION: usize = 8;
// Asset identifier (32), value (8), commitment salt (64), nullifier secret
// (64), and recipient spending-key commitment (64). These bytes are PRIVATE witness material;
// this constant does not introduce a public serialization of an opening.
pub const NOTE_OPENING_BYTES: usize = 32 + 8 + 64 + 64 + 64;

/// Recipient-local spend authority, separate from delivery decryption and the
/// sender-known opening. Never send this key with an output note. A sender
/// learns only its commitment, and cannot derive a spend from the opening.
pub struct SpendingKey {
    secret: Zeroizing<[u8; 64]>,
}

impl SpendingKey {
    pub fn generate(rng: &mut impl rand_core::CryptoRngCore) -> Result<Self, String> {
        let mut secret = Zeroizing::new([0; 64]);
        rng.try_fill_bytes(secret.as_mut())
            .map_err(|_| "PQC spending-key randomness unavailable")?;
        if *secret == [0; 64] {
            return Err("invalid PQC spending key".into());
        }
        Ok(Self { secret })
    }

    /// Shared with a prospective sender, not published in the anonymous spend.
    pub fn commitment(&self, policy: &DeploymentCryptoPolicy) -> Result<Digest512, String> {
        identity(
            b"DEFMI:PQC-NOTE-SPENDING-KEY:v1",
            policy,
            self.secret.as_ref(),
        )
    }
}

/// Wallet-local witness. Deliberately neither Debug, Clone nor Serialize.
/// Possessing this object does not establish accumulator membership or authorize
/// a transaction. Its owned opening buffer is erased when the object is dropped.
pub struct NoteOpening {
    bytes: Zeroizing<[u8; NOTE_OPENING_BYTES]>,
}

impl NoteOpening {
    pub fn generate(
        asset_id: [u8; 32],
        value: u64,
        recipient_spending_commitment: Digest512,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Self, String> {
        recipient_spending_commitment.require_nonzero()?;
        let mut bytes = Zeroizing::new([0; NOTE_OPENING_BYTES]);
        bytes[..32].copy_from_slice(&asset_id);
        bytes[32..40].copy_from_slice(&value.to_be_bytes());
        rng.try_fill_bytes(&mut bytes[40..168])
            .map_err(|_| "PQC note randomness unavailable")?;
        bytes[168..232].copy_from_slice(recipient_spending_commitment.as_bytes());
        Self::from_private_bytes(bytes)
    }

    fn from_private_bytes(bytes: Zeroizing<[u8; NOTE_OPENING_BYTES]>) -> Result<Self, String> {
        if bytes[..32] == [0; 32]
            || bytes[40..104] == [0; 64]
            || bytes[104..168] == [0; 64]
            || bytes[168..232] == [0; 64]
        {
            return Err("invalid private PQC opening".into());
        }
        Ok(Self { bytes })
    }

    pub fn asset_id(&self) -> [u8; 32] {
        self.bytes[..32].try_into().expect("fixed asset width")
    }

    pub fn value(&self) -> u64 {
        u64::from_be_bytes(self.bytes[32..40].try_into().expect("fixed value width"))
    }

    /// SHA-512 over the length-delimited domain, exact deployment policy and
    /// all 232 private bytes. This same preimage must be computed IN the proof.
    pub fn commitment(&self, policy: &DeploymentCryptoPolicy) -> Result<Digest512, String> {
        identity(b"DEFMI:PQC-NOTE-OPENING:v1", policy, self.bytes.as_ref())
    }

    /// Independent domain, full commitment, nullifier secret and recipient-only
    /// spending secret. Knowing the sender-created opening is insufficient.
    /// Neither the source note ID nor the accumulator position is disclosed.
    pub fn nullifier(
        &self,
        policy: &DeploymentCryptoPolicy,
        spending_key: &SpendingKey,
    ) -> Result<Digest512, String> {
        self.require_spending_key(policy, spending_key)?;
        let mut body = Zeroizing::new([0; 192]);
        body[..64].copy_from_slice(self.commitment(policy)?.as_bytes());
        body[64..128].copy_from_slice(&self.bytes[104..168]);
        body[128..].copy_from_slice(spending_key.secret.as_ref());
        identity(b"DEFMI:PQC-NOTE-NULLIFIER:v1", policy, body.as_ref())
    }

    fn require_spending_key(
        &self,
        policy: &DeploymentCryptoPolicy,
        spending_key: &SpendingKey,
    ) -> Result<(), String> {
        if spending_key.commitment(policy)?.as_bytes() != &self.bytes[168..232] {
            return Err("PQC spending key does not own the opening".into());
        }
        Ok(())
    }

    /// Authenticated delivery only, not a proof that a public output is valid.
    /// The caller pins the recipient and delivery context independently of the
    /// envelope. Existing SealedMessage uses a 32-byte application context;
    /// the full-width note commitment is never truncated to produce that value.
    pub fn seal(
        &self,
        policy: &DeploymentCryptoPolicy,
        recipient: &[u8],
        delivery_context: &[u8; 32],
    ) -> Result<PqcNote, String> {
        let commitment = self.commitment(policy)?;
        let encrypted_opening = SealedMessage::seal(
            recipient,
            SealingPurpose::NoteOpening,
            delivery_context,
            self.bytes.as_ref(),
        )
        .map_err(|_| "PQC opening encryption failed")?;
        Ok(PqcNote {
            version: VERSION,
            commitment,
            encrypted_opening,
        })
    }

    /// Sender-local construction for the full private output relation. The
    /// witness stays with the sender's private sharing adapter, never with the
    /// public note or coordinator. Merely returning it does not prove validity.
    pub fn seal_for_private_proof(
        &self,
        policy: &DeploymentCryptoPolicy,
        recipient: &[u8],
        delivery_context: &[u8; 32],
    ) -> Result<(PqcNote, SealingWitness), String> {
        let commitment = self.commitment(policy)?;
        let (encrypted_opening, witness) = SealedMessage::seal_for_private_proof(
            recipient,
            SealingPurpose::NoteOpening,
            delivery_context,
            self.bytes.as_ref(),
        )
        .map_err(|_| "PQC opening proof-witness encryption failed")?;
        Ok((
            PqcNote {
                version: VERSION,
                commitment,
                encrypted_opening,
            },
            witness,
        ))
    }
}

/// A canonical full-width digest, not a legacy curve point or a truncated ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Digest512([u8; 64]);

impl Digest512 {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    fn require_nonzero(&self) -> Result<(), String> {
        if self.0 == [0; 64] {
            return Err("PQC note digest is unbound".into());
        }
        Ok(())
    }
}

impl Serialize for Digest512 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Digest512 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != 128
            || value
                .bytes()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom("noncanonical PQC note digest"));
        }
        let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes.try_into().map_err(|_| {
            serde::de::Error::custom("PQC digest width")
        })?))
    }
}

fn require_policy(policy: &DeploymentCryptoPolicy) -> Result<(), String> {
    policy
        .validate()
        .map_err(|_| "invalid PQC note deployment")?;
    if policy.mode != PqcMode::On || u16::from(policy.version) != VERSION {
        return Err("PQC notes require the exact On deployment version".into());
    }
    Ok(())
}

fn identity(
    domain: &[u8],
    policy: &DeploymentCryptoPolicy,
    body: &[u8],
) -> Result<Digest512, String> {
    require_policy(policy)?;
    let policy = policy.encode().map_err(|_| "PQC note policy encoding")?;
    let mut hash = Sha512::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((policy.len() as u64).to_be_bytes());
    hash.update(policy);
    hash.update((body.len() as u64).to_be_bytes());
    hash.update(body);
    Ok(Digest512(hash.finalize().into()))
}

/// Public note commitment and authenticated encrypted opening. No owner name,
/// long-lived public key, balance, serial secret or source note index is public.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PqcNote {
    pub version: u16,
    pub commitment: Digest512,
    pub encrypted_opening: SealedMessage,
}

impl PqcNote {
    /// Recover an owned opening, verifying both its full commitment and the
    /// recipient's separate spending key. Decryption alone is not ownership.
    /// This wallet check is NOT a public proof verifier or spend authorization.
    pub fn open(
        &self,
        policy: &DeploymentCryptoPolicy,
        recipient: &dyn KemDecapsulator,
        spending_key: &SpendingKey,
        delivery_context: &[u8; 32],
    ) -> Result<NoteOpening, String> {
        require_policy(policy)?;
        self.validate_syntax()?;
        let plaintext = self
            .encrypted_opening
            .open(
                recipient,
                SealingPurpose::NoteOpening,
                delivery_context,
                NOTE_OPENING_BYTES,
            )
            .map_err(|_| "PQC opening authentication failed")?;
        let mut bytes = Zeroizing::new([0; NOTE_OPENING_BYTES]);
        bytes.copy_from_slice(&plaintext);
        let opening = NoteOpening::from_private_bytes(bytes)?;
        if opening.commitment(policy)? != self.commitment {
            return Err("PQC opening commitment mismatch".into());
        }
        opening.require_spending_key(policy, spending_key)?;
        Ok(opening)
    }

    pub fn validate_syntax(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err("unsupported PQC note version".into());
        }
        self.commitment.require_nonzero()?;
        self.encrypted_opening
            .validate(SealingPurpose::NoteOpening, NOTE_OPENING_BYTES)
            .map_err(|_| "invalid PQC note opening envelope".into())
    }

    /// The accumulator commits to the ciphertext too. Computing this ID does
    /// not verify the relation between its hidden plaintext and commitment.
    pub fn id(&self, policy: &DeploymentCryptoPolicy) -> Result<Digest512, String> {
        self.validate_syntax()?;
        identity(
            b"DEFMI:PQC-NOTE:v1",
            policy,
            &serde_json::to_vec(self).map_err(|_| "PQC note encoding")?,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationHead {
    pub reservation_id: Digest512,
    pub authority_digest: Digest512,
    pub asset_id: [u8; 32],
    pub remaining_commitment: Digest512,
    pub sequence: u64,
    pub previous_receipt: Digest512,
    pub expires_at: u64,
}

impl ReservationHead {
    fn validate_syntax(&self) -> Result<(), String> {
        for digest in [
            self.reservation_id,
            self.authority_digest,
            self.remaining_commitment,
            self.previous_receipt,
        ] {
            digest.require_nonzero()?;
        }
        if self.asset_id == [0; 32]
            || self.sequence == u64::MAX
            || self.expires_at == 0
            || self.expires_at > crate::MAX_UNIX_TIME
        {
            return Err("invalid PQC reservation head".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReason {
    Cancelled,
    Expired,
}

/// Each operation needs its own authorization and proved relation. Issuance is
/// not an unrestricted mint; claim is not a public opening of a private note.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Issue {
        issuance_authority: Digest512,
    },
    Reserve {
        mandate: Digest512,
    },
    Fill {
        round_id: [u8; 32],
        slot: u16,
        public_output_digest: [u8; 32],
        securities_reservation: Digest512,
        cash_reservation: Digest512,
    },
    Claim {
        claim_id: Digest512,
    },
    Release {
        reservation_id: Digest512,
        reason: ReleaseReason,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionStatement {
    pub version: u16,
    pub policy: DeploymentCryptoPolicy,
    /// Canonical DeFMI parent and private-note accumulator root are DIFFERENT
    /// commitments. Neither may be substituted for the other.
    pub canonical_parent: [u8; 32],
    pub membership_root: Digest512,
    pub operation_id: Digest512,
    pub operation: Operation,
    pub nullifiers: Vec<Digest512>,
    pub outputs: Vec<PqcNote>,
    pub reservation_heads: Vec<ReservationHead>,
}

impl TransitionStatement {
    pub fn validate_syntax(&self) -> Result<(), String> {
        require_policy(&self.policy)?;
        self.membership_root.require_nonzero()?;
        self.operation_id.require_nonzero()?;
        if self.version != VERSION
            || self.canonical_parent == [0; 32]
            || self.nullifiers.len() > MAX_NOTES_PER_TRANSITION
            || self.outputs.len() > MAX_NOTES_PER_TRANSITION
            || self.reservation_heads.len() > MAX_RESERVATIONS_PER_TRANSITION
        {
            return Err("invalid PQC transition bounds or parent".into());
        }
        let mut seen = BTreeSet::new();
        for nullifier in &self.nullifiers {
            nullifier.require_nonzero()?;
            if !seen.insert(*nullifier) {
                return Err("duplicate PQC nullifier".into());
            }
        }
        seen.clear();
        for note in &self.outputs {
            if !seen.insert(note.id(&self.policy)?) {
                return Err("duplicate PQC output".into());
            }
        }
        seen.clear();
        for head in &self.reservation_heads {
            head.validate_syntax()?;
            if !seen.insert(head.reservation_id) {
                return Err("duplicate PQC reservation head".into());
            }
        }
        match &self.operation {
            Operation::Issue { issuance_authority } => issuance_authority.require_nonzero()?,
            Operation::Reserve { mandate } => mandate.require_nonzero()?,
            Operation::Claim { claim_id } => claim_id.require_nonzero()?,
            Operation::Release { reservation_id, .. } => reservation_id.require_nonzero()?,
            Operation::Fill {
                round_id,
                slot,
                public_output_digest,
                securities_reservation,
                cash_reservation,
            } => {
                securities_reservation.require_nonzero()?;
                cash_reservation.require_nonzero()?;
                if *round_id == [0; 32]
                    || *slot >= 8
                    || *public_output_digest == [0; 32]
                    || securities_reservation == cash_reservation
                {
                    return Err("invalid PQC agreed fill binding".into());
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest512, String> {
        self.validate_syntax()?;
        identity(
            b"DEFMI:PQC-NOTE-TRANSITION:v1",
            &self.policy,
            &serde_json::to_vec(self).map_err(|_| "PQC transition encoding")?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use zkfmi_crypto::{hybrid::kem::HybridKemKey, suite::Version};

    fn policy() -> DeploymentCryptoPolicy {
        DeploymentCryptoPolicy {
            version: Version::V1,
            deployment_id: "pqc-notes-test".into(),
            mode: PqcMode::On,
        }
    }

    fn statement() -> TransitionStatement {
        TransitionStatement {
            version: VERSION,
            policy: policy(),
            canonical_parent: [1; 32],
            membership_root: Digest512([2; 64]),
            operation_id: Digest512([3; 64]),
            operation: Operation::Claim {
                claim_id: Digest512([4; 64]),
            },
            nullifiers: vec![Digest512([5; 64])],
            outputs: vec![],
            reservation_heads: vec![],
        }
    }

    #[test]
    fn digest_wire_is_full_width_and_canonical() {
        let digest = Digest512([0xab; 64]);
        let wire = serde_json::to_string(&digest).unwrap();
        assert_eq!(wire.len(), 130);
        assert_eq!(serde_json::from_str::<Digest512>(&wire).unwrap(), digest);
        assert!(serde_json::from_str::<Digest512>(&wire.to_uppercase()).is_err());
        assert!(serde_json::from_str::<Digest512>(&format!("\"{}\"", "ab".repeat(32))).is_err());
    }

    #[test]
    fn private_commitment_covers_every_opening_field_and_policy() {
        let spending_key = SpendingKey::generate(&mut OsRng).unwrap();
        let owner = spending_key.commitment(&policy()).unwrap();
        let opening = NoteOpening::generate([1; 32], u64::MAX, owner, &mut OsRng).unwrap();
        let commitment = opening.commitment(&policy()).unwrap();
        let nullifier = opening.nullifier(&policy(), &spending_key).unwrap();
        assert_ne!(commitment, nullifier);
        for offset in [0, 32, 39, 40, 103, 104, 167, 168, 231] {
            let mut changed = Zeroizing::new(*opening.bytes);
            changed[offset] ^= 1;
            let changed = NoteOpening::from_private_bytes(changed).unwrap();
            assert_ne!(changed.commitment(&policy()).unwrap(), commitment);
            if offset >= 168 {
                assert!(changed.nullifier(&policy(), &spending_key).is_err());
            } else {
                assert_ne!(
                    changed.nullifier(&policy(), &spending_key).unwrap(),
                    nullifier
                );
            }
        }
        let mut other = policy();
        other.deployment_id.push_str("-other");
        assert_ne!(opening.commitment(&other).unwrap(), commitment);
        other.mode = PqcMode::Off;
        assert!(opening.commitment(&other).is_err());
        assert!(opening.nullifier(&other, &spending_key).is_err());
        assert!(NoteOpening::generate([0; 32], 1, owner, &mut OsRng).is_err());
    }

    #[test]
    fn actual_hybrid_recipient_roundtrip_and_rejections() {
        let recipient = HybridKemKey::generate().unwrap();
        let wrong = HybridKemKey::generate().unwrap();
        let spending_key = SpendingKey::generate(&mut OsRng).unwrap();
        let opening = NoteOpening::generate(
            [6; 32],
            73,
            spending_key.commitment(&policy()).unwrap(),
            &mut OsRng,
        )
        .unwrap();
        let context = [7; 32];
        let note = opening
            .seal(&policy(), &recipient.public_key(), &context)
            .unwrap();
        let recovered = note
            .open(&policy(), &recipient, &spending_key, &context)
            .unwrap();
        assert_eq!(recovered.value(), 73);
        assert_eq!(recovered.asset_id(), [6; 32]);
        assert_eq!(
            recovered.nullifier(&policy(), &spending_key).unwrap(),
            opening.nullifier(&policy(), &spending_key).unwrap()
        );
        assert!(note
            .open(&policy(), &wrong, &spending_key, &context)
            .is_err());
        assert!(note
            .open(&policy(), &recipient, &spending_key, &[8; 32])
            .is_err());
        let mut other = policy();
        other.deployment_id.push_str("-other");
        assert!(note
            .open(&other, &recipient, &spending_key, &context)
            .is_err());
        for field in 0..6 {
            let mut changed = note.clone();
            match field {
                0 => changed.commitment.0[0] ^= 1,
                1 => changed.encrypted_opening.ciphertext[0] ^= 1,
                2 => changed.encrypted_opening.tag[0] ^= 1,
                3 => changed.encrypted_opening.purpose = SealingPurpose::PrivateMpcInput,
                4 => changed.encrypted_opening.kem_ciphertext[32] ^= 1,
                _ => changed.version = 0,
            }
            assert!(changed
                .open(&policy(), &recipient, &spending_key, &context)
                .is_err());
        }
        let wire = serde_json::to_string(&note).unwrap();
        let decoded: PqcNote = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded.id(&policy()).unwrap(), note.id(&policy()).unwrap());
        assert!(!wire.contains("ownership_secret"));
        assert!(!wire.contains("nullifier_secret"));
    }

    #[test]
    fn note_identity_binds_complete_envelope() {
        let recipient = HybridKemKey::generate().unwrap();
        let spending_key = SpendingKey::generate(&mut OsRng).unwrap();
        let opening = NoteOpening::generate(
            [6; 32],
            73,
            spending_key.commitment(&policy()).unwrap(),
            &mut OsRng,
        )
        .unwrap();
        let note = opening
            .seal(&policy(), &recipient.public_key(), &[7; 32])
            .unwrap();
        let id = note.id(&policy()).unwrap();
        for field in 0..4 {
            let mut changed = note.clone();
            match field {
                0 => changed.encrypted_opening.nonce[0] ^= 1,
                1 => changed.encrypted_opening.ciphertext[0] ^= 1,
                2 => changed.encrypted_opening.tag[0] ^= 1,
                _ => changed.commitment.0[0] ^= 1,
            }
            assert_ne!(changed.id(&policy()).unwrap(), id);
        }
        let mut duplicate = statement();
        duplicate.outputs = vec![note.clone(), note];
        assert!(duplicate.validate_syntax().is_err());
    }

    #[test]
    fn sender_known_opening_does_not_grant_recipient_spend_authority() {
        let recipient_spending_key = SpendingKey::generate(&mut OsRng).unwrap();
        let sender_spending_key = SpendingKey::generate(&mut OsRng).unwrap();
        let recipient_commitment = recipient_spending_key.commitment(&policy()).unwrap();
        // This is all the sender needs to construct the complete opening.
        let sender_opening =
            NoteOpening::generate([6; 32], 73, recipient_commitment, &mut OsRng).unwrap();
        assert!(sender_opening
            .nullifier(&policy(), &sender_spending_key)
            .is_err());
        assert!(sender_opening
            .nullifier(&policy(), &recipient_spending_key)
            .is_ok());
        // Substitution changes the note commitment; it does not take over the
        // existing note. The eventual public proof must enforce this relation.
        let mut substituted = Zeroizing::new(*sender_opening.bytes);
        substituted[168..].copy_from_slice(
            sender_spending_key
                .commitment(&policy())
                .unwrap()
                .as_bytes(),
        );
        let substituted = NoteOpening::from_private_bytes(substituted).unwrap();
        assert_ne!(
            substituted.commitment(&policy()).unwrap(),
            sender_opening.commitment(&policy()).unwrap()
        );
        // Correct delivery encryption must not fool the recipient into
        // accepting a note whose spending key is still owned by the sender.
        let delivery_key = HybridKemKey::generate().unwrap();
        let misdirected = substituted
            .seal(&policy(), &delivery_key.public_key(), &[7; 32])
            .unwrap();
        assert!(misdirected
            .open(&policy(), &delivery_key, &recipient_spending_key, &[7; 32])
            .is_err());
    }

    #[test]
    fn transition_binds_parent_membership_and_nullifiers_separately() {
        let original = statement();
        let digest = original.digest().unwrap();
        for field in 0..4 {
            let mut changed = original.clone();
            match field {
                0 => changed.canonical_parent[0] ^= 1,
                1 => changed.membership_root.0[0] ^= 1,
                2 => changed.nullifiers[0].0[0] ^= 1,
                _ => changed.operation_id.0[0] ^= 1,
            }
            assert_ne!(changed.digest().unwrap(), digest);
        }
        let wire = serde_json::to_value(&original).unwrap();
        assert!(wire.get("source_note_ids").is_none());
        assert!(wire.get("membership_indices").is_none());
        let mut unknown = wire;
        unknown["verified"] = true.into();
        assert!(serde_json::from_value::<TransitionStatement>(unknown).is_err());
    }

    #[test]
    fn transitions_reject_unbound_duplicate_and_oversized_inputs() {
        for variant in 0..5 {
            let mut bad = statement();
            match variant {
                0 => bad.nullifiers.push(bad.nullifiers[0]),
                1 => bad.nullifiers[0] = Digest512([0; 64]),
                2 => bad.nullifiers = vec![Digest512([1; 64]); MAX_NOTES_PER_TRANSITION + 1],
                3 => bad.canonical_parent = [0; 32],
                _ => bad.policy.mode = PqcMode::Off,
            }
            assert!(bad.digest().is_err());
        }
    }

    #[test]
    fn fill_requires_distinct_reservations_and_exact_slot_bounds() {
        let mut value = statement();
        value.operation = Operation::Fill {
            round_id: [8; 32],
            slot: 7,
            public_output_digest: [9; 32],
            securities_reservation: Digest512([10; 64]),
            cash_reservation: Digest512([11; 64]),
        };
        assert!(value.digest().is_ok());
        if let Operation::Fill { slot, .. } = &mut value.operation {
            *slot = 8;
        }
        assert!(value.digest().is_err());
        if let Operation::Fill {
            slot,
            cash_reservation,
            securities_reservation,
            ..
        } = &mut value.operation
        {
            *slot = 0;
            *cash_reservation = *securities_reservation;
        }
        assert!(value.digest().is_err());
    }
}
