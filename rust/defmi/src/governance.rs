//! Purpose-bound hybrid governance identities. Enrollment is an operator trust boundary.
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use zkfmi_crypto::{
    backend::{Ed25519Signer, MlDsa65Signer},
    hybrid::signature::HybridSigner,
    key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
    traits::Signer as _,
};

/// Clones share ownership of the secret handle; they do not export or duplicate seeds.
#[derive(Clone)]
pub struct GovernanceSigner {
    signer: Arc<HybridSigner>,
    record: KeyRecord,
}

impl GovernanceSigner {
    pub fn new(signer: HybridSigner, record: KeyRecord) -> Result<Self, String> {
        record.validate().map_err(|e| e.to_string())?;
        if record.purpose != KeyPurpose::Governance
            || record.suite != signer.suite()
            || record.public_key != signer.public_key()
        {
            return Err("governance key does not match its enrolled metadata".into());
        }
        Ok(Self {
            signer: Arc::new(signer),
            record,
        })
    }

    pub fn generate(node: &str, not_before: u64, not_after: u64) -> Result<Self, String> {
        let signer = HybridSigner::generate().map_err(|e| e.to_string())?;
        Self::with_initial_metadata(node, signer, not_before, not_after)
    }

    fn with_initial_metadata(
        node: &str,
        signer: HybridSigner,
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, String> {
        let public_key = signer.public_key();
        let record = KeyRecord {
            participant_id: ParticipantId::new(node).map_err(|e| e.to_string())?,
            key_id: KeyId::new(format!(
                "governance:{}",
                hex::encode(Sha256::digest(&public_key))
            ))
            .map_err(|e| e.to_string())?,
            key_version: 1,
            suite: signer.suite(),
            purpose: KeyPurpose::Governance,
            public_key,
            not_before,
            not_after,
            revoked_at: None,
            rotation_proof: None,
            dekyx_binding: None,
        };
        Self::new(signer, record)
    }

    pub fn verifying_key(&self) -> KeyRecord {
        self.record.clone()
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.signer
            .sign(KeyPurpose::Governance, message)
            .map_err(|e| e.to_string())
    }
}

/// PUBLIC and reconstructible local-development keys, never production enrollment.
/// The two public fixture seeds use distinct labels; no PQ secret derives from an
/// elliptic-curve secret. Real deployments call generate or provision owned handles.
pub fn public_development_keys() -> Result<BTreeMap<String, GovernanceSigner>, String> {
    (0..7)
        .map(|index| {
            let node = format!("node-{index}");
            let classical: [u8; 32] = Sha256::digest(format!("key:{index}").as_bytes()).into();
            let pq: [u8; 32] =
                Sha256::digest(format!("pqc-governance-key:{index}").as_bytes()).into();
            let signer = HybridSigner::new(
                Ed25519Signer::from_seed(&classical),
                MlDsa65Signer::from_seed(&pq),
            );
            Ok((
                node.clone(),
                GovernanceSigner::with_initial_metadata(&node, signer, 0, i64::MAX as u64)?,
            ))
        })
        .collect()
}

#[cfg(all(test, feature = "avalanche"))]
mod tests {
    use super::*;
    use crate::facility::QuorumAuthorizer;

    #[test]
    fn governance_requires_both_components_and_a_current_host_clock() {
        let keys: BTreeMap<String, GovernanceSigner> = BTreeMap::from([
            (
                "a".into(),
                GovernanceSigner::generate("a", 10, 200).unwrap(),
            ),
            (
                "b".into(),
                GovernanceSigner::generate("b", 10, 200).unwrap(),
            ),
        ]);
        let authority = QuorumAuthorizer::new(
            keys.iter()
                .map(|(id, key)| (id.clone(), key.verifying_key()))
                .collect(),
            2,
            1,
            "chain-a",
        )
        .unwrap();
        let statement = [1; 32];
        let root = [2; 32];
        let good = authority.approve(statement, root, &keys).unwrap();
        assert!(!authority.verify(&statement, &root, &good));
        assert!(!authority.at(9).verify(&statement, &root, &good));
        assert!(authority.at(10).verify(&statement, &root, &good));
        assert!(authority.at(199).verify(&statement, &root, &good));
        assert!(!authority.at(200).verify(&statement, &root, &good));
        for mutation in 0..9 {
            let mut bad = good.clone();
            match mutation {
                0 => bad.approvals[0].signature.truncate(64),
                1 => bad.approvals[0].signature[64] ^= 1,
                2 => bad.approvals[0].signature[0] ^= 1,
                3 => bad.signer_epoch += 1,
                4 => bad.committee_digest[0] ^= 1,
                5 => bad.domain = "chain-b".into(),
                6 => bad.before_root[0] ^= 1,
                7 => bad.approvals[1] = bad.approvals[0].clone(),
                _ => {
                    bad.approvals.pop();
                }
            }
            assert!(
                !authority.at(100).verify(&statement, &root, &bad),
                "mutation {mutation}"
            );
        }
        let mut records: BTreeMap<_, _> = keys
            .iter()
            .map(|(id, key)| (id.clone(), key.verifying_key()))
            .collect();
        records.get_mut("a").unwrap().revoked_at = Some(100);
        let revoked = QuorumAuthorizer::new(records, 2, 1, "chain-a").unwrap();
        assert!(!revoked.at(100).verify(&statement, &root, &good));
        assert!(revoked.approve(statement, root, &keys).is_err());
        assert!(!QuorumAuthorizer::read_only()
            .at(100)
            .verify(&statement, &root, &good));
    }
}
