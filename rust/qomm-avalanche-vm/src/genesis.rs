use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use qomm_defmi::facility::QuorumAuthorizer;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 8] = b"QOMMGEN1";
pub const MAX_GENESIS_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeMember {
    pub node_id: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Genesis {
    pub timestamp: i64,
    pub epoch: u64,
    pub threshold: u16,
    pub members: Vec<CommitteeMember>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisConfig {
    pub timestamp: i64,
    pub committee: CommitteeConfig,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitteeConfig {
    pub epoch: u64,
    pub threshold: u16,
    pub members: Vec<MemberConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberConfig {
    #[serde(rename = "nodeID", alias = "nodeId")]
    pub node_id: String,
    pub public_key: String,
}

impl GenesisConfig {
    pub fn into_genesis(mut self) -> Result<Genesis, String> {
        self.committee
            .members
            .sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let members = self
            .committee
            .members
            .into_iter()
            .map(|member| {
                let public_key = hex::decode(&member.public_key)
                    .map_err(|_| format!("member {} publicKey is not hexadecimal", member.node_id))?
                    .try_into()
                    .map_err(|_| format!("member {} publicKey is not 32 bytes", member.node_id))?;
                Ok(CommitteeMember {
                    node_id: member.node_id,
                    public_key,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let genesis = Genesis {
            timestamp: self.timestamp,
            epoch: self.committee.epoch,
            threshold: self.committee.threshold,
            members,
        };
        genesis.validate()?;
        Ok(genesis)
    }
}

impl Genesis {
    pub fn validate(&self) -> Result<(), String> {
        if self.timestamp < 0 {
            return Err("genesis timestamp cannot be negative".into());
        }
        if self.epoch == 0
            || self.members.is_empty()
            || self.members.len() > 64
            || self.threshold == 0
            || usize::from(self.threshold) > self.members.len()
        {
            return Err("genesis contains an invalid k-of-n committee".into());
        }
        let mut node_ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut previous: Option<String> = None;
        for member in &self.members {
            if member.node_id.is_empty()
                || member.node_id.len() > 128
                || !member.node_id.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "._:/+-".contains(character)
                })
                || member.public_key == [0; 32]
                || !node_ids.insert(member.node_id.clone())
                || !keys.insert(member.public_key)
            {
                return Err("genesis committee has an invalid or duplicate member".into());
            }
            if previous
                .as_ref()
                .is_some_and(|value| value >= &member.node_id)
            {
                return Err("genesis committee must be sorted by node ID".into());
            }
            VerifyingKey::from_bytes(&member.public_key)
                .map_err(|_| "genesis committee contains an invalid Ed25519 key".to_string())?;
            previous = Some(member.node_id.clone());
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&self.timestamp.to_be_bytes());
        encoded.extend_from_slice(&self.epoch.to_be_bytes());
        encoded.extend_from_slice(&self.threshold.to_be_bytes());
        encoded.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for member in &self.members {
            let node = member.node_id.as_bytes();
            encoded.extend_from_slice(&(node.len() as u16).to_be_bytes());
            encoded.extend_from_slice(node);
            encoded.extend_from_slice(&member.public_key);
        }
        if encoded.len() > MAX_GENESIS_BYTES {
            return Err("genesis exceeds the one-MiB limit".into());
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.is_empty() || encoded.len() > MAX_GENESIS_BYTES {
            return Err("genesis size is outside 1..=1 MiB".into());
        }
        let mut reader = Reader::new(encoded);
        if reader.take(8)? != MAGIC {
            return Err("genesis magic or version is unsupported".into());
        }
        let timestamp = i64::from_be_bytes(reader.array()?);
        let epoch = u64::from_be_bytes(reader.array()?);
        let threshold = u16::from_be_bytes(reader.array()?);
        let count = usize::from(u16::from_be_bytes(reader.array()?));
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::from(u16::from_be_bytes(reader.array()?));
            let node_id = std::str::from_utf8(reader.take(length)?)
                .map_err(|_| "genesis node ID is not UTF-8".to_string())?
                .to_owned();
            members.push(CommitteeMember {
                node_id,
                public_key: reader.array()?,
            });
        }
        if !reader.is_empty() {
            return Err("genesis contains trailing bytes".into());
        }
        let genesis = Self {
            timestamp,
            epoch,
            threshold,
            members,
        };
        genesis.validate()?;
        Ok(genesis)
    }

    pub fn authorizer(&self, domain: &str) -> Result<QuorumAuthorizer, String> {
        let nodes = self
            .members
            .iter()
            .map(|member| {
                VerifyingKey::from_bytes(&member.public_key)
                    .map(|key| (member.node_id.clone(), key))
                    .map_err(|_| "genesis committee contains an invalid Ed25519 key".to_string())
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        QuorumAuthorizer::new(
            nodes,
            usize::from(self.threshold),
            self.epoch,
            domain.to_owned(),
        )
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "genesis is truncated".to_string())?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "genesis is truncated".to_string())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Genesis {
        Genesis {
            timestamp: 0,
            epoch: 1,
            threshold: 1,
            members: vec![CommitteeMember {
                node_id: "node-0".into(),
                public_key: [1; 32],
            }],
        }
    }

    #[test]
    fn genesis_wire_round_trip_is_exact() {
        let genesis = fixture();
        let encoded = genesis.encode().expect("encode");
        assert_eq!(Genesis::decode(&encoded).expect("decode"), genesis);
    }

    #[test]
    fn rejects_trailing_and_unsorted_members() {
        let mut encoded = fixture().encode().expect("encode");
        encoded.push(0);
        assert!(Genesis::decode(&encoded).is_err());

        let mut genesis = fixture();
        genesis.members.insert(
            0,
            CommitteeMember {
                node_id: "node-1".into(),
                public_key: [2; 32],
            },
        );
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn genesis_config_accepts_avalanche_and_camel_case_node_ids() {
        for node_key in ["nodeID", "nodeId"] {
            let value = serde_json::json!({
                "timestamp": 0,
                "committee": {
                    "epoch": 1,
                    "threshold": 1,
                    "members": [{
                        node_key: "node-0",
                        "publicKey": hex::encode([1_u8; 32]),
                    }],
                },
            });
            let config: GenesisConfig = serde_json::from_value(value).expect("config");
            assert_eq!(config.committee.members[0].node_id, "node-0");
        }
    }
}
