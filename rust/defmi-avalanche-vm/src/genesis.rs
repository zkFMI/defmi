use std::collections::{BTreeMap, BTreeSet};

use defmi::facility::QuorumAuthorizer;
use serde::{Deserialize, Serialize};
use zkfmi_crypto::key::KeyRecord;

const MAGIC: &[u8; 8] = b"QOMMGEN2";
pub const MAX_GENESIS_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitteeMember {
    pub node_id: String,
    pub key: KeyRecord,
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
    pub key: KeyRecord,
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
                Ok(CommitteeMember {
                    node_id: member.node_id,
                    key: member.key,
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
        let mut previous: Option<String> = None;
        for member in &self.members {
            if member.node_id.is_empty()
                || member.node_id.len() > 128
                || !member.node_id.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "._:/+-".contains(character)
                })
                || !node_ids.insert(member.node_id.clone())
            {
                return Err("genesis committee has an invalid or duplicate member".into());
            }
            if previous
                .as_ref()
                .is_some_and(|value| value >= &member.node_id)
            {
                return Err("genesis committee must be sorted by node ID".into());
            }
            previous = Some(member.node_id.clone());
        }
        self.authorizer("genesis-validation")?;
        for member in &self.members {
            member
                .key
                .valid_at(self.timestamp as u64)
                .map_err(|error| error.to_string())?;
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
            let key = serde_json::to_vec(&member.key).map_err(|error| error.to_string())?;
            encoded.extend_from_slice(&(key.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&key);
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
        if count == 0 || count > 64 {
            return Err("invalid genesis committee size".into());
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::from(u16::from_be_bytes(reader.array()?));
            let node_id = std::str::from_utf8(reader.take(length)?)
                .map_err(|_| "genesis node ID is not UTF-8".to_string())?
                .to_owned();
            let key_len = u32::from_be_bytes(reader.array()?) as usize;
            if key_len > 65_536 {
                return Err("genesis key record is oversized".into());
            }
            let bytes = reader.take(key_len)?;
            let key: KeyRecord = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
            if serde_json::to_vec(&key).map_err(|e| e.to_string())? != bytes {
                return Err("genesis key encoding is not canonical".into());
            }
            members.push(CommitteeMember { node_id, key });
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
            .map(|member| (member.node_id.clone(), member.key.clone()))
            .collect::<BTreeMap<_, _>>();
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
                key: defmi::governance::public_development_keys().unwrap()["node-0"]
                    .verifying_key(),
            }],
        }
    }

    #[test]
    fn genesis_wire_round_trip_is_exact() {
        let genesis = fixture();
        let encoded = genesis.encode().expect("encode");
        assert_eq!(Genesis::decode(&encoded).expect("decode"), genesis);
        let mut legacy = encoded;
        legacy[..8].copy_from_slice(b"QOMMGEN1");
        assert!(Genesis::decode(&legacy).is_err());
        let mut classical = genesis;
        classical.members[0].key.suite =
            zkfmi_crypto::suite::Suite::new(zkfmi_crypto::suite::SuiteId::Ed25519);
        classical.members[0].key.public_key.truncate(32);
        assert!(classical.validate().is_err());
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
                key: defmi::governance::public_development_keys().unwrap()["node-1"]
                    .verifying_key(),
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
                        "key": defmi::governance::public_development_keys().unwrap()["node-0"].verifying_key(),
                    }],
                },
            });
            let config: GenesisConfig = serde_json::from_value(value).expect("config");
            assert_eq!(config.committee.members[0].node_id, "node-0");
        }
    }
}
