//! Signed per-slot receipts and self-contained fault evidence.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"QOMM:AUDIT:v1";
const VERSION: &[u8] = b"2";
pub const GENESIS: [u8; 32] = [0; 32];

pub fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    for part in parts {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotSpec {
    pub slot: u64,
    pub mm_set_digest: [u8; 32],
    pub market_digest: [u8; 32],
    pub deadline: u64,
    pub required_receipts: usize,
}

impl SlotSpec {
    pub fn binding(&self) -> [u8; 32] {
        digest(&[
            b"slot",
            &self.slot.to_be_bytes(),
            &self.mm_set_digest,
            &self.market_digest,
        ])
    }
}

#[derive(Clone, Debug)]
pub struct NodeReceipt {
    pub node: u32,
    pub slot: u64,
    pub mm_set_digest: [u8; 32],
    pub market_digest: [u8; 32],
    pub deadline: u64,
    pub prev_state_digest: [u8; 32],
    pub new_state_digest: [u8; 32],
    pub result_digest: [u8; 32],
    pub emitted_at: u64,
    pub signature: Signature,
}

impl NodeReceipt {
    pub fn signed_body(&self) -> [u8; 32] {
        digest(&[
            b"receipt:v2",
            VERSION,
            &self.node.to_be_bytes(),
            &self.slot.to_be_bytes(),
            &self.mm_set_digest,
            &self.market_digest,
            &self.deadline.to_be_bytes(),
            &self.emitted_at.to_be_bytes(),
            &self.prev_state_digest,
            &self.new_state_digest,
            &self.result_digest,
        ])
    }

    pub fn content_digest(&self) -> [u8; 32] {
        digest(&[
            b"content",
            &self.mm_set_digest,
            &self.prev_state_digest,
            &self.new_state_digest,
            &self.result_digest,
        ])
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sign_receipt(
    key: &SigningKey,
    node: u32,
    spec: &SlotSpec,
    prev_state_digest: [u8; 32],
    new_state_digest: [u8; 32],
    result_digest: [u8; 32],
    emitted_at: u64,
    mm_set_digest: Option<[u8; 32]>,
) -> NodeReceipt {
    let mut receipt = NodeReceipt {
        node,
        slot: spec.slot,
        mm_set_digest: mm_set_digest.unwrap_or(spec.mm_set_digest),
        market_digest: spec.market_digest,
        deadline: spec.deadline,
        prev_state_digest,
        new_state_digest,
        result_digest,
        emitted_at,
        signature: Signature::from_bytes(&[0; 64]),
    };
    receipt.signature = key.sign(&receipt.signed_body());
    receipt
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Fault {
    Equivocation,
    OmittedMakers,
    StaleState,
    MissingReceipt,
    BadSignature,
    ForkedState,
}

impl Fault {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::OmittedMakers => "omitted_makers",
            Self::StaleState => "stale_state",
            Self::MissingReceipt => "missing_receipt",
            Self::BadSignature => "bad_signature",
            Self::ForkedState => "forked_state",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub fault: Fault,
    pub node: i64,
    pub slot: u64,
    pub detail: String,
    pub exhibits: Vec<NodeReceipt>,
}

impl Evidence {
    pub fn new(fault: Fault, node: i64, slot: u64, detail: impl Into<String>) -> Self {
        Self {
            fault,
            node,
            slot,
            detail: detail.into(),
            exhibits: Vec::new(),
        }
    }

    fn with_exhibits(mut self, exhibits: Vec<NodeReceipt>) -> Self {
        self.exhibits = exhibits;
        self
    }
}

pub struct AuditLedger {
    node_keys: BTreeMap<u32, VerifyingKey>,
    by_slot: BTreeMap<u64, BTreeMap<u32, Vec<NodeReceipt>>>,
    specs: BTreeMap<u64, SlotSpec>,
    arrived: BTreeMap<(u64, u32), u64>,
    settled_state: BTreeMap<u64, [u8; 32]>,
    pub evidence: Vec<Evidence>,
}

impl AuditLedger {
    pub fn new(node_keys: BTreeMap<u32, VerifyingKey>) -> Self {
        Self {
            node_keys,
            by_slot: BTreeMap::new(),
            specs: BTreeMap::new(),
            arrived: BTreeMap::new(),
            settled_state: BTreeMap::new(),
            evidence: Vec::new(),
        }
    }

    pub fn open_slot(&mut self, spec: SlotSpec) {
        self.by_slot.entry(spec.slot).or_default();
        self.specs.insert(spec.slot, spec);
    }

    pub fn record(&mut self, receipt: NodeReceipt, arrived_at: Option<u64>) -> Vec<Evidence> {
        let Some(spec) = self.specs.get(&receipt.slot) else {
            return vec![Evidence::new(
                Fault::MissingReceipt,
                i64::from(receipt.node),
                receipt.slot,
                "receipt for a slot that was never opened",
            )];
        };
        let Some(key) = self.node_keys.get(&receipt.node) else {
            return vec![Evidence::new(
                Fault::BadSignature,
                i64::from(receipt.node),
                receipt.slot,
                "unknown node",
            )];
        };
        if key
            .verify(&receipt.signed_body(), &receipt.signature)
            .is_err()
        {
            let found = vec![Evidence::new(
                Fault::BadSignature,
                i64::from(receipt.node),
                receipt.slot,
                "signature does not verify",
            )];
            self.evidence.extend(found.clone());
            return found;
        }
        let mut found = Vec::new();
        if receipt.market_digest != spec.market_digest {
            found.push(
                Evidence::new(
                    Fault::StaleState,
                    i64::from(receipt.node),
                    receipt.slot,
                    "signed a market other than the one fixed for this slot",
                )
                .with_exhibits(vec![receipt.clone()]),
            );
        }
        if receipt.deadline != spec.deadline {
            found.push(
                Evidence::new(
                    Fault::StaleState,
                    i64::from(receipt.node),
                    receipt.slot,
                    "signed a deadline other than the one fixed for this slot",
                )
                .with_exhibits(vec![receipt.clone()]),
            );
        }
        if let Some(arrived_at) = arrived_at {
            self.arrived
                .entry((receipt.slot, receipt.node))
                .and_modify(|previous| *previous = (*previous).min(arrived_at))
                .or_insert(arrived_at);
        }
        let existing = self
            .by_slot
            .entry(receipt.slot)
            .or_default()
            .entry(receipt.node)
            .or_default();
        for other in existing.iter() {
            if other.content_digest() != receipt.content_digest() {
                found.push(
                    Evidence::new(
                        Fault::Equivocation,
                        i64::from(receipt.node),
                        receipt.slot,
                        "two signed results for one slot",
                    )
                    .with_exhibits(vec![other.clone(), receipt.clone()]),
                );
            }
        }
        existing.push(receipt.clone());
        if receipt.mm_set_digest != spec.mm_set_digest {
            found.push(
                Evidence::new(
                    Fault::OmittedMakers,
                    i64::from(receipt.node),
                    receipt.slot,
                    "signed a maker set other than the one fixed for this slot",
                )
                .with_exhibits(vec![receipt.clone()]),
            );
        }
        if receipt.slot > 0 {
            if let Some(expected) = self.settled_state.get(&(receipt.slot - 1)) {
                if receipt.prev_state_digest != *expected {
                    found.push(
                        Evidence::new(
                            Fault::StaleState,
                            i64::from(receipt.node),
                            receipt.slot,
                            "continued from a state other than the settled predecessor",
                        )
                        .with_exhibits(vec![receipt]),
                    );
                }
            }
        }
        self.evidence.extend(found.clone());
        found
    }

    pub fn settle(
        &mut self,
        slot: u64,
        now: u64,
    ) -> Result<(Option<[u8; 32]>, Vec<Evidence>), String> {
        let spec = self
            .specs
            .get(&slot)
            .ok_or_else(|| format!("slot {slot} was not opened"))?;
        let receipts = self.by_slot.get(&slot).cloned().unwrap_or_default();
        let mut found = Vec::new();
        for node in self.node_keys.keys() {
            let seen_at = self.arrived.get(&(slot, *node)).copied();
            let fresh = receipts.get(node).is_some_and(|items| {
                items
                    .iter()
                    .any(|receipt| seen_at.unwrap_or(receipt.emitted_at) <= spec.deadline)
            });
            if !fresh {
                found.push(Evidence::new(
                    Fault::MissingReceipt,
                    i64::from(*node),
                    slot,
                    format!(
                        "no receipt by the deadline ({}); observed at {now}",
                        spec.deadline
                    ),
                ));
            }
        }
        let mut tally: BTreeMap<[u8; 32], Vec<u32>> = BTreeMap::new();
        for (node, node_receipts) in &receipts {
            for receipt in node_receipts {
                let when = self
                    .arrived
                    .get(&(slot, *node))
                    .copied()
                    .unwrap_or(receipt.emitted_at);
                if when <= spec.deadline
                    && receipt.mm_set_digest == spec.mm_set_digest
                    && receipt.market_digest == spec.market_digest
                    && receipt.deadline == spec.deadline
                {
                    tally
                        .entry(receipt.new_state_digest)
                        .or_default()
                        .push(*node);
                }
            }
        }
        let mut settled = None;
        if let Some((plurality, nodes)) = tally
            .iter()
            .max_by_key(|(_, nodes)| nodes.iter().copied().collect::<BTreeSet<_>>().len())
        {
            let agreeing = nodes.iter().copied().collect::<BTreeSet<_>>().len();
            for (state, minority) in &tally {
                if state != plurality {
                    for node in minority.iter().copied().collect::<BTreeSet<_>>() {
                        found.push(Evidence::new(
                            Fault::ForkedState,
                            i64::from(node),
                            slot,
                            "signed a new state that the quorum did not agree with",
                        ));
                    }
                }
            }
            if agreeing < spec.required_receipts {
                found.push(Evidence::new(Fault::MissingReceipt, -1, slot,
                    format!("only {agreeing} agreeing receipts, {} required; the slot is unresolved and the state does not advance",
                            spec.required_receipts)));
            } else {
                settled = Some(*plurality);
                self.settled_state.insert(slot, *plurality);
            }
        }
        self.evidence.extend(found.clone());
        Ok((settled, found))
    }

    pub fn settled_state(&self, slot: u64) -> [u8; 32] {
        self.settled_state.get(&slot).copied().unwrap_or(GENESIS)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Slash {
    pub node: u32,
    pub slot: u64,
    pub fault: Fault,
    pub amount: u64,
    pub remaining_bond: u64,
}

pub struct BondLedger {
    pub bonds: BTreeMap<u32, u64>,
    pub penalties: BTreeMap<Fault, u64>,
    pub slashed: Vec<Slash>,
}

impl BondLedger {
    pub fn new(bonds: BTreeMap<u32, u64>) -> Self {
        Self {
            bonds,
            penalties: BTreeMap::from([
                (Fault::Equivocation, 1_000_000),
                (Fault::ForkedState, 500_000),
                (Fault::OmittedMakers, 500_000),
                (Fault::StaleState, 250_000),
                (Fault::BadSignature, 250_000),
                (Fault::MissingReceipt, 50_000),
            ]),
            slashed: Vec::new(),
        }
    }

    pub fn apply(&mut self, evidence: &[Evidence]) -> Vec<Slash> {
        let mut applied = Vec::new();
        for item in evidence {
            let Ok(node) = u32::try_from(item.node) else {
                continue;
            };
            let Some(bond) = self.bonds.get_mut(&node) else {
                continue;
            };
            let amount = (*bond).min(*self.penalties.get(&item.fault).unwrap_or(&0));
            if amount == 0 {
                continue;
            }
            *bond -= amount;
            let slash = Slash {
                node,
                slot: item.slot,
                fault: item.fault,
                amount,
                remaining_bond: *bond,
            };
            self.slashed.push(slash.clone());
            applied.push(slash);
        }
        applied
    }
}
