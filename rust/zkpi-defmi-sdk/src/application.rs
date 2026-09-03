use crate::{SdkError, SdkResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MANIFEST_DOMAIN: &[u8] = b"ZKPI:DEFMI:APPLICATION-MANIFEST:v1";
const SCHEMA_DOMAIN: &[u8] = b"ZKPI:DEFMI:APPLICATION-SCHEMA:v1";

const QOMM_INPUT_SCHEMA: &[u8] =
    b"qomm/v1:hidden-rfq+maker-policy+inventory+reference-market+standing-mandates";
const QOMM_SETTLEMENT_SCHEMA: &[u8] =
    b"qomm/v1:complete-quote+price-limit+typed-zkpi+threshold-dvp+atomic-pool-split";
const OCLOB_INPUT_SCHEMA: &[u8] =
    b"oclob/v1:hidden-limit-orders+price-time-priority+committed-public-book";
const OCLOB_SETTLEMENT_SCHEMA: &[u8] =
    b"oclob/v1:matched-order-pair+typed-zkpi+threshold-dvp+atomic-book-transition";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ApplicationId(String);

impl ApplicationId {
    pub fn parse(value: impl Into<String>) -> SdkResult<Self> {
        let value = value.into();
        let bytes = value.as_bytes();
        let valid = (3..=64).contains(&bytes.len())
            && bytes[0].is_ascii_lowercase()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
            && !bytes.windows(2).any(|pair| {
                matches!(pair[0], b'.' | b'-' | b'_') && matches!(pair[1], b'.' | b'-' | b'_')
            });
        if !valid {
            return Err(SdkError::InvalidManifest(
                "application_id must be 3-64 lowercase ASCII characters with single separators"
                    .into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowKind {
    RequestDrivenDealerMarket,
    ContinuousLimitOrderBook,
    PaymentStream,
    CrossDomainDeliveryVersusPayment,
}

impl WorkflowKind {
    fn tag(self) -> u8 {
        match self {
            Self::RequestDrivenDealerMarket => 1,
            Self::ContinuousLimitOrderBook => 2,
            Self::PaymentStream => 3,
            Self::CrossDomainDeliveryVersusPayment => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputVisibility {
    CommitteeOnly,
    PublicTermsHiddenIdentity,
    Public,
}

impl InputVisibility {
    fn tag(self) -> u8 {
        match self {
            Self::CommitteeOnly => 1,
            Self::PublicTermsHiddenIdentity => 2,
            Self::Public => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketView {
    WinnerOnly,
    CommittedAggregate,
    PublicOrders,
}

impl MarketView {
    fn tag(self) -> u8 {
        match self {
            Self::WinnerOnly => 1,
            Self::CommittedAggregate => 2,
            Self::PublicOrders => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementVisibility {
    CommitmentsAndProofs,
    ParticipantsOnly,
    PublicAmounts,
}

impl SettlementVisibility {
    fn tag(self) -> u8 {
        match self {
            Self::CommitmentsAndProofs => 1,
            Self::ParticipantsOnly => 2,
            Self::PublicAmounts => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeProfile {
    pub nodes: u16,
    /// Minimum colluding nodes required to reconstruct one protected input.
    pub privacy_threshold: u16,
    /// Independent approvals required for an application authorization.
    pub authorization_quorum: u16,
}

impl CommitteeProfile {
    pub fn validate(self) -> SdkResult<()> {
        if self.nodes < 2
            || self.privacy_threshold < 2
            || self.privacy_threshold > self.nodes
            || self.authorization_quorum < 2
            || self.authorization_quorum > self.nodes
        {
            return Err(SdkError::InvalidManifest(
                "committee thresholds must be between two and the node count".into(),
            ));
        }
        Ok(())
    }

    pub const fn qomm_seven_node() -> Self {
        Self {
            nodes: 7,
            privacy_threshold: 2,
            authorization_quorum: 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApplicationManifest {
    pub application_id: ApplicationId,
    pub version: u32,
    pub workflow: WorkflowKind,
    pub input_visibility: InputVisibility,
    pub market_view: MarketView,
    pub settlement_visibility: SettlementVisibility,
    pub committee: CommitteeProfile,
    pub input_schema_digest: [u8; 32],
    pub settlement_schema_digest: [u8; 32],
}

impl ApplicationManifest {
    pub fn validate(&self) -> SdkResult<()> {
        self.committee.validate()?;
        if self.version == 0
            || self.input_schema_digest == [0; 32]
            || self.settlement_schema_digest == [0; 32]
            || self.input_schema_digest == self.settlement_schema_digest
        {
            return Err(SdkError::InvalidManifest(
                "version and both distinct schema digests are required".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> SdkResult<[u8; 32]> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(MANIFEST_DOMAIN);
        put_bytes(&mut hash, self.application_id.as_str().as_bytes());
        hash.update(self.version.to_be_bytes());
        hash.update([self.workflow.tag()]);
        hash.update([self.input_visibility.tag()]);
        hash.update([self.market_view.tag()]);
        hash.update([self.settlement_visibility.tag()]);
        hash.update(self.committee.nodes.to_be_bytes());
        hash.update(self.committee.privacy_threshold.to_be_bytes());
        hash.update(self.committee.authorization_quorum.to_be_bytes());
        hash.update(self.input_schema_digest);
        hash.update(self.settlement_schema_digest);
        Ok(hash.finalize().into())
    }
}

pub fn schema_digest(name: &str, schema: &[u8]) -> SdkResult<[u8; 32]> {
    if name.is_empty() || name.len() > 128 || schema.is_empty() || schema.len() > (1 << 20) {
        return Err(SdkError::InvalidManifest(
            "schema name or bytes are outside fixed SDK bounds".into(),
        ));
    }
    let mut hash = Sha256::new();
    hash.update(SCHEMA_DOMAIN);
    put_bytes(&mut hash, name.as_bytes());
    put_bytes(&mut hash, schema);
    Ok(hash.finalize().into())
}

pub fn qomm_manifest_v1() -> ApplicationManifest {
    ApplicationManifest {
        application_id: ApplicationId::parse("qomm").expect("static QOMM application id"),
        version: 1,
        workflow: WorkflowKind::RequestDrivenDealerMarket,
        input_visibility: InputVisibility::CommitteeOnly,
        market_view: MarketView::WinnerOnly,
        settlement_visibility: SettlementVisibility::CommitmentsAndProofs,
        committee: CommitteeProfile::qomm_seven_node(),
        input_schema_digest: schema_digest("qomm-input-v1", QOMM_INPUT_SCHEMA)
            .expect("static QOMM input schema"),
        settlement_schema_digest: schema_digest("qomm-settlement-v1", QOMM_SETTLEMENT_SCHEMA)
            .expect("static QOMM settlement schema"),
    }
}

pub fn oclob_manifest_v1() -> ApplicationManifest {
    ApplicationManifest {
        application_id: ApplicationId::parse("oclob").expect("static OCLOB application id"),
        version: 1,
        workflow: WorkflowKind::ContinuousLimitOrderBook,
        input_visibility: InputVisibility::CommitteeOnly,
        market_view: MarketView::CommittedAggregate,
        settlement_visibility: SettlementVisibility::CommitmentsAndProofs,
        committee: CommitteeProfile::qomm_seven_node(),
        input_schema_digest: schema_digest("oclob-input-v1", OCLOB_INPUT_SCHEMA)
            .expect("static OCLOB input schema"),
        settlement_schema_digest: schema_digest("oclob-settlement-v1", OCLOB_SETTLEMENT_SCHEMA)
            .expect("static OCLOB settlement schema"),
    }
}

fn put_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qomm_and_oclob_are_distinct_applications() {
        let qomm = qomm_manifest_v1();
        let oclob = oclob_manifest_v1();
        assert_ne!(qomm.application_id, oclob.application_id);
        assert_ne!(qomm.digest().unwrap(), oclob.digest().unwrap());
        assert_ne!(qomm.input_schema_digest, oclob.input_schema_digest);
    }

    #[test]
    fn rejects_ambiguous_ids_and_committees() {
        assert!(ApplicationId::parse("QOMM").is_err());
        assert!(ApplicationId::parse("qomm--prod").is_err());
        let mut manifest = qomm_manifest_v1();
        manifest.committee.authorization_quorum = 8;
        assert!(manifest.digest().is_err());
    }
}
