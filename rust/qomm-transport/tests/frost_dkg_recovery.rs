//! Crash recovery at the only dangerous FROST provisioning boundary: after
//! recipient-encrypted round-two packages exist but before every node has
//! durably finalized the common group key.

use qomm_transport::frost_coordinator::{finalize_frost_dkg, prepare_frost_dkg};
use qomm_transport::proof_client::ProofPartyRpc;
use qomm_transport::proof_party::{ProofParty, ProofPartyConfig, ProofRequest};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct LocalParty {
    node: u16,
    root: PathBuf,
    party: ProofParty,
    next_id: u64,
}

impl LocalParty {
    fn config(node: u16, root: &Path) -> ProofPartyConfig {
        ProofPartyConfig {
            node,
            allowed_root: root.to_path_buf(),
            state_file: root.join(format!("node-{node}.qps")),
            state_passphrase: vec![node as u8 + 1; 32],
            n_mm: 4,
            n_parties: 7,
            threshold: 2,
            amount_bits: 16,
            price_bits: 32,
            remainder_bits: 32,
            complete_quote_proof: true,
            quote_eligibility_bits: 34,
            quote_span_bits: 32,
            trusted_defmi_receipt_public: None,
            allow_health_signing: false,
        }
    }

    fn new(node: u16, root: &Path) -> Self {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            node,
            root: root.to_path_buf(),
            party: ProofParty::new(Self::config(node, root)).unwrap(),
            next_id: 1,
        }
    }

    fn restart(&mut self) {
        self.party = ProofParty::new(Self::config(self.node, &self.root)).unwrap();
        self.next_id = 1;
    }
}

impl ProofPartyRpc for LocalParty {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let response = self.party.handle(ProofRequest {
            id,
            method: method.into(),
            params,
        });
        if !response.ok {
            return Err(response
                .error
                .unwrap_or_else(|| "local proof party rejected the request".into()));
        }
        response
            .result
            .ok_or_else(|| "local proof party omitted its result".into())
    }
}

fn configure_and_confirm(parties: &mut [LocalParty], session: [u8; 32]) {
    let entries = Value::Array(
        parties
            .iter_mut()
            .map(|party| {
                party
                    .call("frost_identity", json!({"session": hex::encode(session)}))
                    .unwrap()
            })
            .collect(),
    );
    let confirmations = Value::Array(
        parties
            .iter_mut()
            .map(|party| {
                let response = party
                    .call(
                        "frost_configure_peers",
                        json!({
                            "session": hex::encode(session),
                            "entries": entries.clone(),
                        }),
                    )
                    .unwrap();
                json!({
                    "party": response["party"].clone(),
                    "confirmation": response["confirmation"].clone(),
                })
            })
            .collect(),
    );
    for party in parties {
        party
            .call(
                "frost_confirm_peers",
                json!({"confirmations": confirmations.clone()}),
            )
            .unwrap();
    }
}

fn assert_ready(parties: &mut [LocalParty]) {
    for party in parties {
        let health = party.call("health", Value::Null).unwrap();
        assert_eq!(health["frost_ready"], true);
        assert_eq!(health["frost_peer_manifest_persisted"], false);
        assert_eq!(health["frost_dkg_round1_persisted"], false);
        assert_eq!(health["frost_dkg_round2_persisted"], false);
    }
}

#[test]
fn durable_signing_state_rejects_a_changed_proof_configuration() {
    let root = TempDir::new().unwrap();
    let party = LocalParty::new(0, root.path());
    let stable_identity = party.party.instance_id();
    drop(party);

    let mut changed = LocalParty::config(0, root.path());
    changed.complete_quote_proof = false;
    let error = ProofParty::new(changed).err().unwrap();
    assert!(error.contains("security configuration"));

    let restored = ProofParty::new(LocalParty::config(0, root.path())).unwrap();
    assert_eq!(restored.instance_id(), stable_identity);
}

#[test]
fn coordinator_can_restart_before_every_node_reaches_round_two() {
    let root = TempDir::new().unwrap();
    let mut parties = (0_u16..7)
        .map(|node| LocalParty::new(node, root.path()))
        .collect::<Vec<_>>();
    let session = [0x31; 32];
    configure_and_confirm(&mut parties, session);

    // Only part of the committee has emitted a durable round-one package when
    // the coordinator and two different-stage nodes disappear.
    for party in parties.iter_mut().take(3) {
        party.call("frost_dkg_round1", json!({})).unwrap();
    }
    parties[0].restart();
    parties[5].restart();

    let plan = prepare_frost_dkg(&mut parties, session).unwrap();
    finalize_frost_dkg(&mut parties, &plan).unwrap();
    assert_ready(&mut parties);
}

#[test]
fn coordinator_reconstructs_a_missing_journal_after_partial_round_two() {
    let root = TempDir::new().unwrap();
    let mut parties = (0_u16..7)
        .map(|node| LocalParty::new(node, root.path()))
        .collect::<Vec<_>>();
    let session = [0x32; 32];
    configure_and_confirm(&mut parties, session);
    let broadcasts = Value::Array(
        parties
            .iter_mut()
            .map(|party| party.call("frost_dkg_round1", json!({})).unwrap())
            .collect(),
    );

    // Four nodes persisted recipient-encrypted round two, but the coordinator
    // died before it could write a complete journal.  A fresh coordinator must
    // recover the same broadcasts and encrypted packages from the nodes.
    for party in parties.iter_mut().take(4) {
        party
            .call(
                "frost_dkg_round2",
                json!({"broadcasts": broadcasts.clone()}),
            )
            .unwrap();
    }
    parties[1].restart();
    parties[5].restart();

    let plan = prepare_frost_dkg(&mut parties, session).unwrap();
    finalize_frost_dkg(&mut parties, &plan).unwrap();
    assert_ready(&mut parties);
}

#[test]
fn journaled_round_two_survives_node_and_coordinator_restart() {
    let root = TempDir::new().unwrap();
    let mut parties = (0_u16..7)
        .map(|node| LocalParty::new(node, root.path()))
        .collect::<Vec<_>>();
    let session = [0x42; 32];
    let plan = prepare_frost_dkg(&mut parties, session).unwrap();

    // Three different proof processes disappear after emitting their encrypted
    // packages. Their encrypted state must carry enough information to finish
    // the exact journaled transcript, without another round-one secret.
    for node in [0_usize, 3, 6] {
        parties[node].restart();
    }
    let public = finalize_frost_dkg(&mut parties, &plan).unwrap();

    // A coordinator may lose one or more final replies. Replaying the exact
    // journal is idempotent, while every node returns the same public package.
    let replayed = finalize_frost_dkg(&mut parties, &plan).unwrap();
    assert_eq!(public.serialize().unwrap(), replayed.serialize().unwrap());
    assert_ready(&mut parties);
    for party in &mut parties {
        let health = party.call("health", Value::Null).unwrap();
        assert!(health["state_generation"].as_u64().unwrap() >= 3);
    }
}
