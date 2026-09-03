//! The execution-binding adapter over the native threshold proof crates.
//!
//! production implementation in `qomm-proofs::threshold_sigma`; this module
//! deliberately builds on that one so the commitment, the node share, and the
//! threshold proof all refer to the same bytes.

use curve25519_dalek::scalar::Scalar;
use qomm_proofs::threshold_sigma::{deal, verify_share, PartyId, ShareSet};
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};

pub use qomm_proofs::quote_proof::{
    Gate, MakerProof, MakerWitness, Public as QuotePublic, QuoteCircuit, QuoteProof, Registered,
    RegisteredPolicy,
};
pub use qomm_proofs::threshold_gadgets::{commitment_from_shares, Shared};
pub use qomm_proofs::threshold_quote::{
    check_circuit_field, deal_quote_shares, joint_prove_quote, shares_from_circuit, CircuitWires,
    NodeQuoteView, QuoteAssemblyTranscript, QuoteShares,
};
pub use qomm_proofs::threshold_range::{
    joint_prove_range_from_contributions, verify_threshold_range, NodeValueShares,
    RangeAssemblyTranscript, ThresholdRangeProof, ValueShares,
};
pub use qomm_proofs::threshold_sigma::{
    audit_partials, joint_opening_from_shares, joint_prove_opening, OpeningAssemblyTranscript,
    ScalarShares,
};

#[derive(Clone, Debug)]
pub struct DealtValue {
    pub position: usize,
    pub shares: ShareSet,
    pub label: String,
}

#[derive(Clone, Debug)]
pub struct BoundInputs {
    pub n_parties: usize,
    pub threshold: usize,
    pub values: Vec<DealtValue>,
}

impl BoundInputs {
    pub fn party_file(&self, party: PartyId) -> Result<Vec<Scalar>, String> {
        self.values
            .iter()
            .map(|value| {
                value
                    .shares
                    .value_shares
                    .get(&party)
                    .copied()
                    .ok_or_else(|| {
                        format!("value {} has no share for party {party}", value.position)
                    })
            })
            .collect()
    }

    pub fn commitments(&self) -> Vec<curve25519_dalek::ristretto::RistrettoPoint> {
        self.values
            .iter()
            .map(|value| value.shares.commitment)
            .collect()
    }
}

pub struct BindingDealer {
    pub key: Pedersen,
    pub parties: Vec<PartyId>,
    pub threshold: usize,
    pub dealt: Vec<DealtValue>,
    pub labels: Vec<String>,
}

impl BindingDealer {
    pub fn new(
        key: Pedersen,
        n_parties: usize,
        threshold: usize,
        labels: Vec<String>,
    ) -> Result<Self, String> {
        if n_parties < 2 * threshold + 1 {
            return Err(format!(
                "{n_parties} parties cannot carry a threshold of {threshold}"
            ));
        }
        Ok(Self {
            key,
            parties: (1..=n_parties).collect(),
            threshold,
            dealt: Vec::new(),
            labels,
        })
    }

    pub fn deal<R: RngCore + CryptoRng>(
        &mut self,
        value: i64,
        position: usize,
        rng: &mut R,
    ) -> Result<Vec<Scalar>, String> {
        if position != self.dealt.len() {
            return Err("input positions must be dealt in circuit order".into());
        }
        let value = if value >= 0 {
            Scalar::from(value as u64)
        } else {
            -Scalar::from(value.unsigned_abs())
        };
        let blinding = Scalar::random(&mut *rng);
        let shares = deal(
            &self.key,
            &value,
            &blinding,
            &self.parties,
            self.threshold,
            rng,
        )?;
        let output = self
            .parties
            .iter()
            .map(|party| shares.value_shares[party])
            .collect();
        self.dealt.push(DealtValue {
            position,
            shares,
            label: self.labels.get(position).cloned().unwrap_or_default(),
        });
        Ok(output)
    }

    pub fn bound(&self) -> BoundInputs {
        BoundInputs {
            n_parties: self.parties.len(),
            threshold: self.threshold,
            values: self.dealt.clone(),
        }
    }
}

pub fn check_share(dealt: &DealtValue, party: PartyId, key: &Pedersen) -> bool {
    verify_share(key, &dealt.shares, party)
}

pub fn check_all(key: &Pedersen, bound: &BoundInputs) -> Vec<(PartyId, usize)> {
    bound
        .values
        .iter()
        .flat_map(|dealt| {
            (1..=bound.n_parties)
                .filter(|party| !verify_share(key, &dealt.shares, *party))
                .map(|party| (party, dealt.position))
                .collect::<Vec<_>>()
        })
        .collect()
}
