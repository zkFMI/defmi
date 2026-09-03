use crate::application::ApplicationManifest;
use crate::{SdkError, SdkResult};
use qomm_transport::product_proof_coordinator::{
    ExecutionAttestationInput, ProductExecutionRequest,
};
use sha2::{Digest, Sha256};

const BINDING_DOMAIN: &[u8] = b"ZKPI:DEFMI:APPLICATION-EXECUTION:v1";
const PRODUCT_COMMITTEE_NODES: usize = 7;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionNodeDigest {
    pub batch_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub stdout_digest: [u8; 32],
    pub stderr_digest: [u8; 32],
    pub persistence_digest: [u8; 32],
}

impl ExecutionNodeDigest {
    fn into_transport(self) -> ExecutionAttestationInput {
        ExecutionAttestationInput {
            batch_digest: self.batch_digest,
            source_digest: self.source_digest,
            stdout_digest: self.stdout_digest,
            stderr_digest: self.stderr_digest,
            persistence_digest: self.persistence_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionShape {
    pub lane: usize,
    pub slot: u64,
    pub generation: u64,
    pub frame_count: u64,
    pub input_count: u64,
    pub order_digest: [u8; 32],
    pub nodes: Vec<ExecutionNodeDigest>,
}

pub struct ApplicationExecutionPlan {
    manifest_digest: [u8; 32],
    job_id: [u8; 32],
    binding_digest: [u8; 32],
    request: ProductExecutionRequest,
}

impl ApplicationExecutionPlan {
    pub fn new(manifest: &ApplicationManifest, shape: ExecutionShape) -> SdkResult<Self> {
        let manifest_digest = manifest.digest()?;
        if usize::from(manifest.committee.nodes) != PRODUCT_COMMITTEE_NODES
            || shape.nodes.len() != PRODUCT_COMMITTEE_NODES
        {
            return Err(SdkError::InvalidExecution(
                "the current verifier-complete product adapter requires exactly seven nodes".into(),
            ));
        }
        let request = ProductExecutionRequest {
            lane: shape.lane,
            slot: shape.slot,
            generation: shape.generation,
            frame_count: shape.frame_count,
            input_count: shape.input_count,
            order_digest: shape.order_digest,
            nodes: shape
                .nodes
                .into_iter()
                .map(ExecutionNodeDigest::into_transport)
                .collect(),
        };
        let job_id = request.job_id().map_err(SdkError::InvalidExecution)?;
        let binding_digest = application_binding(
            manifest_digest,
            job_id,
            shape.slot,
            shape.lane,
            shape.generation,
            shape.order_digest,
        );
        Ok(Self {
            manifest_digest,
            job_id,
            binding_digest,
            request,
        })
    }

    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub fn job_id(&self) -> [u8; 32] {
        self.job_id
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }

    pub fn product_request(&self) -> &ProductExecutionRequest {
        &self.request
    }

    pub fn into_product_request(self) -> ProductExecutionRequest {
        self.request
    }
}

fn application_binding(
    manifest_digest: [u8; 32],
    job_id: [u8; 32],
    slot: u64,
    lane: usize,
    generation: u64,
    order_digest: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(BINDING_DOMAIN);
    hash.update(manifest_digest);
    hash.update(job_id);
    hash.update(slot.to_be_bytes());
    hash.update((lane as u64).to_be_bytes());
    hash.update(generation.to_be_bytes());
    hash.update(order_digest);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{oclob_manifest_v1, qomm_manifest_v1};

    fn shape(persistence_delta: u8) -> ExecutionShape {
        ExecutionShape {
            lane: 4,
            slot: 9,
            generation: 1,
            frame_count: 1,
            input_count: 7,
            order_digest: [11; 32],
            nodes: (0..7)
                .map(|node| ExecutionNodeDigest {
                    batch_digest: [20 + node; 32],
                    source_digest: [31; 32],
                    stdout_digest: [40 + node; 32],
                    stderr_digest: [50 + node; 32],
                    persistence_digest: [60 + node + persistence_delta; 32],
                })
                .collect(),
        }
    }

    #[test]
    fn binds_application_and_exact_execution() {
        let qomm = ApplicationExecutionPlan::new(&qomm_manifest_v1(), shape(0)).unwrap();
        let oclob = ApplicationExecutionPlan::new(&oclob_manifest_v1(), shape(0)).unwrap();
        assert_eq!(qomm.job_id(), oclob.job_id());
        assert_ne!(qomm.binding_digest(), oclob.binding_digest());

        let changed = ApplicationExecutionPlan::new(&qomm_manifest_v1(), shape(1)).unwrap();
        assert_ne!(qomm.job_id(), changed.job_id());
        assert_ne!(qomm.binding_digest(), changed.binding_digest());
    }

    #[test]
    fn refuses_partial_execution_committee() {
        let mut incomplete = shape(0);
        incomplete.nodes.pop();
        assert!(ApplicationExecutionPlan::new(&qomm_manifest_v1(), incomplete).is_err());
    }
}
