//! Live five-validator driver. Uses the ordinary SDK HTTP transport and RPCs.
use super::*;
use defmi::avalanche::{AvalancheClient, AvalancheRpcClient, CanonicalConfidentialClaim};
use defmi_avalanche_vm::genesis::{CommitteeMember, Genesis};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static EPOCH: AtomicU64 = AtomicU64::new(0);
pub fn enabled() -> bool {
    env::var("DEFMI_ASSET_PRIVACY_NATIVE").as_deref() == Ok("1")
}
pub fn wall() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}
pub fn reset_epoch() {
    EPOCH.store(wall(), Ordering::SeqCst);
}
pub fn moment(logical: u64) -> u64 {
    if !enabled() {
        return logical;
    }
    let base = EPOCH.load(Ordering::SeqCst);
    match logical {
        800 => base + 80,
        900 => base + 90,
        1000 => base + 600,
        10_000 => base + 3600,
        _ => wall(),
    }
}
pub fn wait_expiry() {
    if enabled() {
        println!(
            "waiting for native consensus time to pass reservation expiry {}",
            moment(900)
        );
        while wall() <= moment(900) {
            thread::sleep(Duration::from_millis(200));
        }
    }
}

pub struct Network {
    pub clients: Vec<AvalancheRpcClient>,
    pub chain_id: String,
    pub output: PathBuf,
}
impl Network {
    pub fn connect(
        output: &PathBuf,
        signers: &BTreeMap<String, GovernanceSigner>,
    ) -> Result<Option<Self>, String> {
        if !enabled() {
            return Ok(None);
        }
        let genesis = Genesis {
            timestamp: wall().saturating_sub(1) as i64,
            epoch: 1,
            threshold: 3,
            members: signers
                .iter()
                .map(|(name, signer)| CommitteeMember {
                    node_id: name.clone(),
                    key: signer.verifying_key(),
                })
                .collect(),
            deployment_crypto_policy: None,
        };
        fs::write(output.join("genesis.bin"), genesis.encode()?).map_err(err)?;
        let started = Instant::now();
        while !output.join("network.json").is_file() {
            if started.elapsed() > Duration::from_secs(300) {
                return Err("native network did not become ready".into());
            }
            thread::sleep(Duration::from_millis(200));
        }
        let config: Value =
            serde_json::from_slice(&fs::read(output.join("network.json")).map_err(err)?)
                .map_err(err)?;
        let chain_id = config["chain_id"]
            .as_str()
            .ok_or("native chain ID missing")?
            .to_string();
        let uris = config["node_uris"]
            .as_array()
            .ok_or("native node URIs missing")?;
        if uris.len() != 5 {
            return Err("native acceptance requires five AvalancheGo validators".into());
        }
        let clients = uris
            .iter()
            .map(|uri| {
                AvalancheRpcClient::new(
                    &format!(
                        "{}/ext/bc/{chain_id}",
                        uri.as_str().ok_or("invalid native node URI")?
                    ),
                    Duration::from_secs(15),
                    true,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let network = Self {
            clients,
            chain_id,
            output: output.clone(),
        };
        network.roots(State::default().root())?;
        reset_epoch();
        Ok(Some(network))
    }

    pub fn roots(&self, expected: [u8; 32]) -> Result<Vec<String>, String> {
        let started = Instant::now();
        loop {
            let result = self
                .clients
                .iter()
                .map(AvalancheClient::state_root)
                .collect::<Result<Vec<_>, _>>();
            if let Ok(roots) = &result {
                if roots.iter().all(|root| *root == expected) {
                    return Ok(roots.iter().map(hex::encode).collect());
                }
            }
            if started.elapsed() > Duration::from_secs(60) {
                return Err(format!("native validators did not become ready or converge to the reconstructed root: {result:?}"));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn accept(
        &self,
        transaction: &TransactionEnvelope,
    ) -> Result<(Block, Vec<u8>, Value), String> {
        let value: Value = serde_json::from_slice(&transaction.encode()?).map_err(err)?;
        let method = value["method"]
            .as_str()
            .ok_or("transaction method missing")?;
        let response = self.clients[0].call(method, value["params"].clone())?;
        let tx_id = transaction.id()?.to_string();
        if response["txID"] != tx_id {
            return Err("native submit returned another transaction".into());
        }
        let started = Instant::now();
        let receipt = loop {
            let receipt = self.clients[0].call("defmivm.txStatus", json!({"txID":tx_id}))?;
            if receipt["status"] == "accepted" {
                break receipt;
            }
            if receipt["status"] == "rejected" {
                return Err(format!(
                    "native transaction rejected: {}",
                    receipt["reason"]
                ));
            }
            if started.elapsed() > Duration::from_secs(90) {
                return Err("native transaction acceptance timed out".into());
            }
            thread::sleep(Duration::from_millis(100));
        };
        let last = self.clients[0].call("defmivm.lastAccepted", json!({}))?;
        if last["blockID"] != receipt["blockID"] {
            return Err("native last accepted block differs from receipt".into());
        }
        let bytes = BASE64
            .decode(
                last["blockBytes"]
                    .as_str()
                    .ok_or("native block bytes missing")?,
            )
            .map_err(err)?;
        let block = Block::decode(&bytes)?;
        if block.transactions != vec![transaction.encode()?]
            || Id::digest(&bytes).to_string() != receipt["blockID"]
        {
            return Err(
                "native accepted block does not contain the exact submitted transaction".into(),
            );
        }
        Ok((block, bytes, receipt))
    }

    pub fn reject(
        &self,
        tx: &[u8],
        reason: &str,
        expected_root: [u8; 32],
    ) -> Result<Value, String> {
        let value: Value = serde_json::from_slice(tx).map_err(err)?;
        let result = self.clients[0].call(
            value["method"]
                .as_str()
                .ok_or("transaction method missing")?,
            value["params"].clone(),
        );
        let observation = match result {
            Err(error) if error.contains(reason) => json!({"rpc_rejection":error}),
            Ok(response) => {
                let expected = TransactionEnvelope::decode(tx)?.id()?.to_string();
                if response["txID"] != expected {
                    return Err("native rejection returned another transaction ID".into());
                }
                let started = Instant::now();
                loop {
                    let status =
                        self.clients[0].call("defmivm.txStatus", json!({"txID":expected}))?;
                    if status["status"] == "rejected" {
                        if !status["reason"]
                            .as_str()
                            .is_some_and(|error| error.contains(reason))
                        {
                            return Err(format!("native rejection has another reason: {status}"));
                        }
                        break json!({"rejected_transaction":status});
                    }
                    if status["status"] == "accepted" {
                        if reason != "already applied" {
                            return Err(format!(
                                "native chain accepted an invalid transaction: {status}"
                            ));
                        }
                        break json!({"idempotent_existing_receipt":status});
                    }
                    if started.elapsed() > Duration::from_secs(90) {
                        return Err("native rejection status timed out".into());
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
            other => {
                return Err(format!(
                    "native rejection reached an unexpected boundary: {other:?}"
                ))
            }
        };
        self.roots(expected_root)?;
        Ok(observation)
    }

    pub fn notes(
        &self,
        expected_root: [u8; 32],
    ) -> Result<Vec<(NoteOutput, AssetIdentity)>, String> {
        let mut after = None;
        let mut notes = Vec::new();
        let mut page_number = 0;
        loop {
            let page = self.clients[0].confidential_note_page(after, 3)?;
            if page.state_root != expected_root {
                return Err("native wallet scan changed root between pages".into());
            }
            page_number += 1;
            after = page.next;
            notes.extend(page.notes);
            if after.is_none() {
                break;
            }
            if page_number > 100 {
                return Err("native wallet scan did not terminate".into());
            }
        }
        for (_, identity) in &notes {
            let (root, canonical) =
                self.clients[0].confidential_asset_identity(identity.commitment)?;
            if root != expected_root || canonical != *identity {
                return Err("native identity lookup differs from wallet page".into());
            }
        }
        fs::write(self.output.join("native-wallet-scan.json"),serde_json::to_vec_pretty(&json!({
            "state_root":hex::encode(expected_root),"pages":page_number,"asset_filter_sent":false,
            "notes":notes.iter().map(|(note,identity)|json!({"note":note_json(note),"identity":identity})).collect::<Vec<_>>()
        })).map_err(err)?).map_err(err)?;
        Ok(notes)
    }

    pub fn restart_readback(&self, expected_root: [u8; 32]) -> Result<(), String> {
        let before = self.roots(expected_root)?;
        fs::write(
            self.output.join("ready-for-restart.json"),
            serde_json::to_vec(&json!({"root":hex::encode(expected_root)})).map_err(err)?,
        )
        .map_err(err)?;
        let started = Instant::now();
        while !self.output.join("restart-complete").is_file() {
            if started.elapsed() > Duration::from_secs(240) {
                return Err("native restart did not complete".into());
            }
            thread::sleep(Duration::from_millis(200));
        }
        let after = self.roots(expected_root)?;
        fs::write(self.output.join("restart-readback.json"),serde_json::to_vec_pretty(&json!({
            "node":"node3","before_roots":before,"after_roots":after,"elapsed_seconds":started.elapsed().as_secs_f64()
        })).map_err(err)?).map_err(err)?;
        Ok(())
    }

    pub fn claim(
        &self,
        claim_id: [u8; 32],
        root: [u8; 32],
    ) -> Result<CanonicalConfidentialClaim, String> {
        let snapshot = self.clients[0].confidential_note_claim(claim_id)?;
        if snapshot.claim.state_root != root {
            return Err("native claim readback has another root".into());
        }
        Ok(snapshot)
    }
}
