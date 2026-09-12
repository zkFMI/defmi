//! Shared canonical optimistic client for QOMM and OCLOB. These methods submit
//! real DeFMI transactions and read consensus-owned claims; no local timer can
//! grant settlement authority.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use defmi::avalanche::{AcceptedTransition, AvalancheClient, AvalancheRpcClient};
use defmi::facility::QuorumApproval;
use rand_core::RngCore;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
pub use zkpi_committee::optimistic::*;
pub use zkpi_committee::proof_party::ProofParty;

pub struct OptimisticClient<'a> {
    pub rpc: &'a AvalancheRpcClient,
}

fn attempt() -> Digest32 {
    let mut nonce = [0; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Created only by a canonical RPC readback. Consumers still include the
/// claim reference in the signed fill, which the VM checks independently.
#[derive(Clone, Debug)]
pub struct CanonicalOptimisticFinality {
    claim: Claim,
}
impl CanonicalOptimisticFinality {
    pub fn claim(&self) -> &Claim {
        &self.claim
    }
}

impl OptimisticClient<'_> {
    fn issue(
        &self,
        method: &str,
        params: Value,
        expected: Digest32,
    ) -> Result<AcceptedTransition, String> {
        let result = self.rpc.call(method, params)?;
        let id = result
            .get("txID")
            .and_then(Value::as_str)
            .ok_or("optimistic transaction has no ID")?;
        let accepted = self
            .rpc
            .wait_accepted(id, Duration::MAX, Duration::from_millis(100))?;
        if accepted.statement != expected {
            return Err("ledger accepted another optimistic statement".into());
        }
        Ok(accepted)
    }

    fn governed<T: Serialize>(
        &self,
        method: &str,
        field: &str,
        operation: &str,
        value: &T,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        let expected = command_digest(operation, value)?;
        if approval.statement != expected {
            return Err("approval names another optimistic command".into());
        }
        let mut params = json!({
            "expectedBeforeRoot": hex::encode(approval.before_root),
            "approval": {
                "statement":hex::encode(approval.statement),"signerEpoch":approval.signer_epoch,
                "suite":approval.suite,"committeeDigest":hex::encode(approval.committee_digest),
                "domain":approval.domain,"beforeRoot":hex::encode(approval.before_root),
                "approvals":approval.approvals.iter().map(|s| json!({"nodeID":s.node_id,"signature":hex::encode(&s.signature)})).collect::<Vec<_>>()
            }
        });
        params[field] = serde_json::to_value(value).map_err(|e| e.to_string())?;
        let accepted = self.issue(method, params, expected)?;
        if accepted.before_root != approval.before_root {
            return Err("optimistic command was accepted on another parent".into());
        }
        Ok(accepted)
    }

    pub fn enroll(
        &self,
        policy: &OptimisticPolicy,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        self.governed(
            "defmivm.issueOptimisticPolicy",
            "policy",
            "enroll",
            policy,
            approval,
        )
    }
    pub fn register(
        &self,
        execution: &RegisteredExecution,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        self.governed(
            "defmivm.issueOptimisticExecution",
            "execution",
            "register",
            execution,
            approval,
        )
    }
    pub fn transfer_bond(
        &self,
        transfer: &BondTransfer,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        self.governed(
            "defmivm.issueOptimisticBond",
            "transfer",
            "bond",
            transfer,
            approval,
        )
    }
    pub fn settle_accounts(
        &self,
        settlement: &defmi::application_settlement::OptimisticAccountSettlement,
        approval: &QuorumApproval,
    ) -> Result<AcceptedTransition, String> {
        settlement.statement()?;
        self.governed(
            "defmivm.issueOptimisticAccountSettlement",
            "settlement",
            "account_settlement",
            settlement,
            approval,
        )
    }
    pub fn propose(&self, proposal: &Proposal) -> Result<AcceptedTransition, String> {
        self.issue(
            "defmivm.issueOptimisticProposal",
            json!({"proposal":proposal}),
            proposal.id()?,
        )
    }
    pub fn challenge(&self, challenge: &Challenge) -> Result<AcceptedTransition, String> {
        self.issue(
            "defmivm.issueOptimisticChallenge",
            json!({"challenge":challenge}),
            command_digest("challenge", challenge)?,
        )
    }
    pub fn advance(&self, claim: Digest32) -> Result<AcceptedTransition, String> {
        self.issue(
            "defmivm.issueOptimisticAdvance",
            json!({"claim":claim,"attempt":attempt()}),
            command_digest("advance", &claim)?,
        )
    }
    pub fn answer(&self, claim: Digest32, proof: &[u8]) -> Result<AcceptedTransition, String> {
        let expected = command_digest("answer", &(claim, hex::encode(Sha256::digest(proof))))?;
        self.issue(
            "defmivm.issueOptimisticAnswer",
            json!({"claim":claim,"proof":BASE64.encode(proof),"attempt":attempt()}),
            expected,
        )
    }
    pub fn finalized(
        &self,
        id: Digest32,
        context: &ExecutionContext,
        output: Digest32,
    ) -> Result<CanonicalOptimisticFinality, String> {
        let claim = self.claim(id)?;
        if claim.proposal.context != *context
            || claim.proposal.output_root != output
            || !matches!(claim.status, ClaimStatus::Finalized { .. })
        {
            return Err("canonical optimistic claim is not finalized for this result".into());
        }
        Ok(CanonicalOptimisticFinality { claim })
    }

    /// One shared challenge driver for both applications. Client time only
    /// schedules an advance request; the ledger owns every deadline decision.
    pub fn await_finality(
        &self,
        proposal: &Proposal,
        mut produce_proof: impl FnMut() -> Result<Vec<u8>, String>,
        mut on_update: impl FnMut(&Claim),
    ) -> Result<CanonicalOptimisticFinality, String> {
        let id = proposal.id()?;
        let mut last = None;
        let mut proof = None;
        loop {
            let claim = self.claim(id)?;
            if claim.proposal != *proposal {
                return Err("canonical claim differs from the submitted proposal".into());
            }
            if last.as_ref() != Some(&claim.status) {
                on_update(&claim);
                last = Some(claim.status.clone());
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let action = match claim.status {
                ClaimStatus::Finalized { .. } => return Ok(CanonicalOptimisticFinality { claim }),
                ClaimStatus::Rejected { .. } => {
                    return Err(format!(
                        "optimistic claim {} was rejected; settlement is forbidden",
                        hex::encode(id)
                    ))
                }
                ClaimStatus::Challenged {
                    response_deadline, ..
                } if now < response_deadline => {
                    if proof.is_none() {
                        match produce_proof() {
                            Ok(bytes) => proof = Some(bytes),
                            Err(error) => {
                                let current = self.claim(id)?;
                                if current.proposal != *proposal {
                                    return Err(
                                        "canonical claim changed during proof generation".into()
                                    );
                                }
                                if current.status != claim.status {
                                    continue;
                                }
                                return Err(error);
                            }
                        }
                    }
                    // Proof generation may outlive the response window, or a
                    // second watcher may already have answered this challenge.
                    let current = self.claim(id)?;
                    if current.proposal != *proposal {
                        return Err("canonical claim changed during proof generation".into());
                    }
                    if current.status != claim.status {
                        continue;
                    }
                    self.answer(id, proof.as_deref().ok_or("challenge proof is missing")?)
                }
                ClaimStatus::Challenged { .. } => self.advance(id),
                ClaimStatus::Pending | ClaimStatus::Proven { .. }
                    if now >= claim.challenge_deadline =>
                {
                    self.advance(id)
                }
                _ => {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            };
            if let Err(error) = action {
                let current = self.claim(id)?;
                if current.proposal != *proposal {
                    return Err("canonical claim changed during finality submission".into());
                }
                // A rejected duplicate is harmless only when canonical state
                // actually progressed. Do not hide network or verifier errors.
                if current.status == claim.status {
                    return Err(error);
                }
            }
        }
    }
    pub fn claim(&self, id: Digest32) -> Result<Claim, String> {
        let result = self.rpc.call(
            "defmivm.optimisticClaim",
            json!({"claimID":hex::encode(id)}),
        )?;
        let claim: Claim = serde_json::from_value(
            result
                .get("claim")
                .cloned()
                .ok_or("canonical claim is missing")?,
        )
        .map_err(|e| e.to_string())?;
        if claim.proposal.id()? != id {
            return Err("canonical readback names another optimistic claim".into());
        }
        claim
            .proposal
            .verify(&claim.policy, claim.accepted_at, &ApplicationAuthentication)?;
        Ok(claim)
    }
    pub fn policy(&self, id: Digest32) -> Result<OptimisticPolicy, String> {
        let result = self.rpc.call(
            "defmivm.optimisticPolicy",
            json!({"policyID":hex::encode(id)}),
        )?;
        let policy: OptimisticPolicy = serde_json::from_value(
            result
                .get("policy")
                .cloned()
                .ok_or("canonical policy is missing")?,
        )
        .map_err(|e| e.to_string())?;
        if policy.digest()? != id {
            return Err("canonical readback names another optimistic policy".into());
        }
        Ok(policy)
    }
}
