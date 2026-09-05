use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::id::Id;

pub const MAX_JSON_DEPTH: usize = 64;

pub const ISSUE_METHODS: &[&str] = &[
    "defmivm.issueAethelProvider",
    "defmivm.issueAethelStream",
    "defmivm.issueAethelStreamTransition",
    "defmivm.issueAethelSeries",
    "defmivm.issueAethelCredentialIssuer",
    "defmivm.issueAethelCredentialStatus",
    "defmivm.issueAethelCreditDecision",
    "defmivm.issueAethelGuarantee",
    "defmivm.issueAethelFundingQuote",
    "defmivm.issueAethelReceivable",
    "defmivm.issueAethelDefault",
    "defmivm.issueAethelGuaranteeClaim",
    "defmivm.issueAethelGuaranteeRelease",
    "defmivm.issueAethelProviderKeyRotation",
    "defmivm.issueAethelProviderStatus",
    "defmivm.issueDeccpClearingBook",
    "defmivm.issueDeccpMember",
    "defmivm.issueDeccpGuaranteeFacility",
    "defmivm.issueAsset",
    "defmivm.issueCSDIssuer",
    "defmivm.issueCSDIssuerControl",
    "defmivm.issueAdmissionCommittee",
    "defmivm.issueSettlementVerifier",
    "defmivm.issueAdmissionBatch",
    "defmivm.issueAdmissionAdvance",
    "defmivm.issueProductReservation",
    "defmivm.issueStandingNotePool",
    "defmivm.issueStandingNotePoolAllocation",
    "defmivm.issueStandingPoolProductSettlement",
    "defmivm.issueNoteProductReservation",
    "defmivm.issueApplicationReserveScope",
    "defmivm.issueApplicationNoteReservation",
    "defmivm.issueProductRelease",
    "defmivm.issueNoteProductRelease",
    "defmivm.issueNoteProductNoFillRelease",
    "defmivm.issueAccount",
    "defmivm.issueNote",
    "defmivm.issueNoteClaimMaterialization",
    "defmivm.issueGuarantor",
    "defmivm.issueCreditGrant",
    "defmivm.issueCreditTransition",
    "defmivm.issueCreditControl",
    "defmivm.issueCreditAmendment",
    "defmivm.issueSettlement",
    "defmivm.issueNoteSettlement",
    "defmivm.issueProductSettlement",
    "defmivm.issueProductSettlementBatch",
    "defmivm.issueNoteProductSettlement",
    "defmivm.issueNoteProductSettlementBatch",
    "defmivm.issueCrossDomainDomain",
    "defmivm.issueCrossDomainCommittee",
    "defmivm.issueCrossDomainPrepare",
    "defmivm.issueCrossDomainArm",
    "defmivm.issueCrossDomainClaim",
    "defmivm.issueCrossDomainRefund",
    "defmivm.issueCrossDomainObserveClaim",
    "defmivm.issueBojParticipant",
    "defmivm.issueBojCollateralPledge",
    "defmivm.issueBojCollateralRevalue",
    "defmivm.issueBojIntradayReserve",
    "defmivm.issueBojIntradayRelease",
    "defmivm.issueBojCollateralReturn",
    "defmivm.issueBojFundsReceipt",
    "defmivm.issueBojOtherExposure",
    "defmivm.issueBojSimultaneousDvp",
    "defmivm.issueBojEndOfDay",
    "defmivm.issueBojOpenBusinessDay",
    "defmivm.issueParticipantRegistry",
    "defmivm.issueParticipant",
    "defmivm.issueParticipantControl",
    "defmivm.issueParticipantKeyRotation",
    "defmivm.issueMpcService",
    "defmivm.issueParticipantAccountBinding",
    "defmivm.issueParticipantServiceBinding",
    "defmivm.issueStandingMandate",
    "defmivm.issueStandingMandateControl",
    "defmivm.issueMandateReservation",
    "defmivm.issueMandateReservationTransition",
    "defmivm.issueParticipantProductReservation",
    "defmivm.issueParticipantNoteProductReservation",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionEnvelope {
    pub method: String,
    pub params: Value,
}

impl TransactionEnvelope {
    pub fn new(method: impl Into<String>, params: Value) -> Result<Self, String> {
        let transaction = Self {
            method: method.into(),
            params,
        };
        transaction.validate()?;
        Ok(transaction)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !ISSUE_METHODS.contains(&self.method.as_str()) {
            return Err("transaction method is not an allowed DeFMI issue method".into());
        }
        if !self.params.is_object() {
            return Err("transaction parameters must be a JSON object".into());
        }
        validate_json(&self.params, 0)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(&canonical_value(
            serde_json::to_value(self).map_err(|e| e.to_string())?,
        ))
        .map_err(|error| error.to_string())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let transaction =
            Self::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
        deserializer.end().map_err(|error| error.to_string())?;
        transaction.validate()?;
        if transaction.encode()? != bytes {
            return Err("transaction JSON is not in canonical encoding".into());
        }
        Ok(transaction)
    }

    pub fn id(&self) -> Result<Id, String> {
        self.encode().map(|bytes| Id::digest(&bytes))
    }
}

fn validate_json(value: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err("transaction JSON nesting exceeds the limit".into());
    }
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) if number.is_u64() || number.is_i64() => Ok(()),
        Value::Number(_) => Err("transaction JSON cannot contain floating-point numbers".into()),
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_json(value, depth + 1)),
        Value::Object(values) => values
            .values()
            .try_for_each(|value| validate_json(value, depth + 1)),
    }
}

fn canonical_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_value).collect()),
        Value::Object(values) => {
            let mut keys = values.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                sorted.insert(
                    key.clone(),
                    canonical_value(values.get(&key).expect("key was collected").clone()),
                );
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalizes_object_key_order() {
        let transaction =
            TransactionEnvelope::new("defmivm.issueAsset", json!({"z": 1, "a": {"y": 2, "b": 3}}))
                .expect("transaction");
        let encoded = transaction.encode().expect("encode");
        assert_eq!(
            TransactionEnvelope::decode(&encoded).expect("decode"),
            transaction
        );
        assert!(std::str::from_utf8(&encoded)
            .expect("UTF-8")
            .contains("\"a\":{\"b\":3,\"y\":2}"));
    }

    #[test]
    fn rejects_float_and_non_issue_method() {
        assert!(TransactionEnvelope::new("defmivm.stateRoot", json!({})).is_err());
        assert!(TransactionEnvelope::new("defmivm.issueAsset", json!({"x": 1.5})).is_err());
    }

    #[test]
    fn accepts_atomic_standing_pool_product_settlement_method() {
        TransactionEnvelope::new("defmivm.issueStandingPoolProductSettlement", json!({}))
            .expect("atomic standing-pool settlement is a consensus issue method");
    }
}
