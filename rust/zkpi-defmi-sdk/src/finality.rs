use crate::{SdkError, SdkResult};
use ed25519_dalek::VerifyingKey;
use qomm_defmi::facility::SettlementReceipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FINALITY_DOMAIN: &[u8] = b"ZKPI:DEFMI:APPLICATION-FINALITY:v1";
const READBACK_DOMAIN: &[u8] = b"ZKPI:DEFMI:CANONICAL-READBACK:v1";
const MAX_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadbackKind {
    NoteReservation,
    CreditHold,
    StandingNotePool,
    NoteClaim,
    Account,
    Asset,
    Custom,
}

impl ReadbackKind {
    fn tag(self) -> u8 {
        match self {
            Self::NoteReservation => 1,
            Self::CreditHold => 2,
            Self::StandingNotePool => 3,
            Self::NoteClaim => 4,
            Self::Account => 5,
            Self::Asset => 6,
            Self::Custom => 255,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalReadback {
    pub kind: ReadbackKind,
    pub resource_id: [u8; 32],
    pub state_root: [u8; 32],
}

impl CanonicalReadback {
    pub fn new(kind: ReadbackKind, resource_id: [u8; 32], state_root: [u8; 32]) -> SdkResult<Self> {
        if resource_id == [0; 32] || state_root == [0; 32] {
            return Err(SdkError::InvalidFinality(
                "canonical readback lacks a resource or state root".into(),
            ));
        }
        Ok(Self {
            kind,
            resource_id,
            state_root,
        })
    }

    fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(READBACK_DOMAIN);
        hash.update([self.kind.tag()]);
        hash.update(self.resource_id);
        hash.update(self.state_root);
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalTransition {
    pub transaction_id: String,
    pub block_id: String,
    pub height: u64,
    pub statement: [u8; 32],
    pub before_state_root: [u8; 32],
    pub after_state_root: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApplicationSettlementReceipt {
    pub application_binding: [u8; 32],
    pub transaction_id: String,
    pub block_id: String,
    pub height: u64,
    pub statement: [u8; 32],
    pub before_state_root: [u8; 32],
    pub after_state_root: [u8; 32],
    pub canonical_readback_digest: [u8; 32],
    pub receipt_digest: [u8; 32],
}

/// Accept a consensus transition only when the application binding and
/// independently computed statement match and every required canonical
/// resource has been read back at the accepted state root.
pub fn accept_canonical_transition(
    application_binding: [u8; 32],
    transition: &CanonicalTransition,
    expected_statement: [u8; 32],
    expected_before_root: [u8; 32],
    readbacks: &[CanonicalReadback],
) -> SdkResult<ApplicationSettlementReceipt> {
    if application_binding == [0; 32]
        || transition.transaction_id.is_empty()
        || transition.transaction_id.len() > MAX_ID_BYTES
        || transition.block_id.is_empty()
        || transition.block_id.len() > MAX_ID_BYTES
        || transition.height == 0
        || expected_statement == [0; 32]
        || expected_before_root == [0; 32]
        || transition.statement != expected_statement
        || transition.before_state_root != expected_before_root
        || transition.after_state_root == [0; 32]
        || transition.after_state_root == transition.before_state_root
        || readbacks.is_empty()
        || readbacks
            .iter()
            .any(|readback| readback.state_root != transition.after_state_root)
    {
        return Err(SdkError::InvalidFinality(
            "transition, expected statement, or canonical readbacks do not describe one accepted state"
                .into(),
        ));
    }
    let canonical_readback_digest = digest_readbacks(readbacks);
    let receipt_digest = finality_digest(
        application_binding,
        &transition.transaction_id,
        &transition.block_id,
        transition.height,
        transition.statement,
        transition.before_state_root,
        transition.after_state_root,
        canonical_readback_digest,
    );
    Ok(ApplicationSettlementReceipt {
        application_binding,
        transaction_id: transition.transaction_id.clone(),
        block_id: transition.block_id.clone(),
        height: transition.height,
        statement: transition.statement,
        before_state_root: transition.before_state_root,
        after_state_root: transition.after_state_root,
        canonical_readback_digest,
        receipt_digest,
    })
}

/// Verify a chain-neutral DeFMI facility receipt with its pinned signing key,
/// then bind it to one application execution. This is used by deployments
/// whose finality surface is the signed facility rather than Avalanche block
/// acceptance.
pub fn accept_signed_facility_receipt(
    application_binding: [u8; 32],
    receipt: &SettlementReceipt,
    verifying_key: &VerifyingKey,
    expected_statement: [u8; 32],
    expected_before_root: [u8; 32],
) -> SdkResult<ApplicationSettlementReceipt> {
    if application_binding == [0; 32]
        || !receipt.verify(verifying_key)
        || receipt.operation_id == [0; 32]
        || receipt.nullifier == [0; 32]
        || receipt.statement != expected_statement
        || receipt.before_root != expected_before_root
        || receipt.after_root == [0; 32]
        || receipt.after_root == receipt.before_root
        || receipt.committed_at_ns == 0
    {
        return Err(SdkError::InvalidFinality(
            "signed facility receipt failed its key, statement, or state-root checks".into(),
        ));
    }
    let transaction_id = hex::encode(receipt.operation_id);
    let block_id = hex::encode(receipt.digest().map_err(SdkError::InvalidFinality)?);
    let readback_digest = receipt.digest().map_err(SdkError::InvalidFinality)?;
    let receipt_digest = finality_digest(
        application_binding,
        &transaction_id,
        &block_id,
        receipt.committed_at_ns,
        receipt.statement,
        receipt.before_root,
        receipt.after_root,
        readback_digest,
    );
    Ok(ApplicationSettlementReceipt {
        application_binding,
        transaction_id,
        block_id,
        height: receipt.committed_at_ns,
        statement: receipt.statement,
        before_state_root: receipt.before_root,
        after_state_root: receipt.after_root,
        canonical_readback_digest: readback_digest,
        receipt_digest,
    })
}

fn digest_readbacks(readbacks: &[CanonicalReadback]) -> [u8; 32] {
    let mut digests = readbacks
        .iter()
        .map(CanonicalReadback::digest)
        .collect::<Vec<_>>();
    digests.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(READBACK_DOMAIN);
    hash.update((digests.len() as u64).to_be_bytes());
    for digest in digests {
        hash.update(digest);
    }
    hash.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn finality_digest(
    application_binding: [u8; 32],
    transaction_id: &str,
    block_id: &str,
    height: u64,
    statement: [u8; 32],
    before_root: [u8; 32],
    after_root: [u8; 32],
    readback_digest: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FINALITY_DOMAIN);
    hash.update(application_binding);
    hash.update((transaction_id.len() as u64).to_be_bytes());
    hash.update(transaction_id.as_bytes());
    hash.update((block_id.len() as u64).to_be_bytes());
    hash.update(block_id.as_bytes());
    hash.update(height.to_be_bytes());
    hash.update(statement);
    hash.update(before_root);
    hash.update(after_root);
    hash.update(readback_digest);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn canonical_finality_requires_matching_readbacks() {
        let transition = CanonicalTransition {
            transaction_id: "tx-1".into(),
            block_id: "block-1".into(),
            height: 9,
            statement: [3; 32],
            before_state_root: [4; 32],
            after_state_root: [5; 32],
        };
        let readbacks = vec![
            CanonicalReadback::new(ReadbackKind::CreditHold, [6; 32], [5; 32]).unwrap(),
            CanonicalReadback::new(ReadbackKind::NoteClaim, [7; 32], [5; 32]).unwrap(),
        ];
        let receipt =
            accept_canonical_transition([2; 32], &transition, [3; 32], [4; 32], &readbacks)
                .unwrap();
        assert_ne!(receipt.receipt_digest, [0; 32]);

        let stale =
            vec![CanonicalReadback::new(ReadbackKind::CreditHold, [6; 32], [8; 32]).unwrap()];
        assert!(
            accept_canonical_transition([2; 32], &transition, [3; 32], [4; 32], &stale,).is_err()
        );
    }

    #[test]
    fn signed_facility_finality_rejects_another_key() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let mut receipt = SettlementReceipt {
            operation_id: [1; 32],
            nullifier: [2; 32],
            statement: [3; 32],
            before_root: [4; 32],
            after_root: [5; 32],
            previous_receipt: [6; 32],
            committed_at_ns: 8,
            elapsed_ns: 9,
            request_bytes: 10,
            response_bytes: 11,
            database_bytes_before: 12,
            database_bytes_after: 13,
            signature: ed25519_dalek::Signature::from_bytes(&[0; 64]),
        };
        receipt.signature = signing.sign(&receipt.unsigned().unwrap());
        assert!(accept_signed_facility_receipt(
            [9; 32],
            &receipt,
            &signing.verifying_key(),
            [3; 32],
            [4; 32],
        )
        .is_ok());
        let other = SigningKey::from_bytes(&[8; 32]);
        assert!(accept_signed_facility_receipt(
            [9; 32],
            &receipt,
            &other.verifying_key(),
            [3; 32],
            [4; 32],
        )
        .is_err());
    }
}
