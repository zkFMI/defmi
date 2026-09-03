//! Encrypted, crash-atomic lifecycle for anonymous legal-entity credentials.
//!
//! Credentials are delivered once to the verified entity. The service keeps
//! only their public points, encrypted entity metadata, signed audit events and
//! current cohort registries. Updating, revoking, merging or reinstating a
//! control group rotates its point, so a venue that accepts only the newest
//! registry rejects every older presentation.

use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use qomm_proofs::kyb::{verify_registry, BusinessAttributes, KybCredential, SignedCohortRegistry};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::key_management::{
    decrypt_authenticated, derive_secret_key, encrypt_authenticated, FileLock,
};

const MAGIC: &[u8; 8] = b"QOMMKYB1";
const AAD: &[u8] = b"QOMM:KYB:LIFECYCLE-STATE:v1";
const EVENT_DOMAIN: &[u8] = b"QOMM:KYB:LIFECYCLE-EVENT:v1";
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityStatus {
    Active,
    Revoked,
    Merged,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EntityRecord {
    legal_entity_ref_digest: String,
    public_point: String,
    attributes: BusinessAttributes,
    revision: u64,
    status: EntityStatus,
    merged_into: Option<String>,
    updated_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    Pending,
    Upheld,
    Reinstated,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AppealRecord {
    control_group_id: String,
    reason_digest: String,
    opened_at: u64,
    resolved_at: Option<u64>,
    status: AppealStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuditEvent {
    sequence: u64,
    at: u64,
    kind: String,
    subject_digest: String,
    payload_digest: String,
    previous: String,
    digest: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredRegistry {
    cohort: String,
    registry_epoch: u64,
    expires_at: u64,
    points: Vec<String>,
    issuer: String,
    registry_id: String,
    signature: String,
}

impl StoredRegistry {
    fn from_registry(registry: &SignedCohortRegistry) -> Self {
        Self {
            cohort: registry.cohort.clone(),
            registry_epoch: registry.registry_epoch,
            expires_at: registry.expires_at,
            points: registry
                .points
                .iter()
                .map(|point| hex::encode(point.compress().to_bytes()))
                .collect(),
            issuer: hex::encode(registry.issuer.to_bytes()),
            registry_id: hex::encode(registry.registry_id),
            signature: hex::encode(registry.signature.to_bytes()),
        }
    }

    fn registry(&self) -> Result<SignedCohortRegistry, String> {
        let issuer: [u8; 32] = hex::decode(&self.issuer)
            .map_err(|_| "stored KYB issuer is malformed".to_string())?
            .try_into()
            .map_err(|_| "stored KYB issuer is malformed".to_string())?;
        let registry_id: [u8; 32] = hex::decode(&self.registry_id)
            .map_err(|_| "stored KYB registry identifier is malformed".to_string())?
            .try_into()
            .map_err(|_| "stored KYB registry identifier is malformed".to_string())?;
        let signature: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| "stored KYB registry signature is malformed".to_string())?
            .try_into()
            .map_err(|_| "stored KYB registry signature is malformed".to_string())?;
        Ok(SignedCohortRegistry {
            cohort: self.cohort.clone(),
            registry_epoch: self.registry_epoch,
            expires_at: self.expires_at,
            points: self
                .points
                .iter()
                .map(|point| {
                    let raw: [u8; 32] = hex::decode(point)
                        .map_err(|_| "stored KYB point is malformed".to_string())?
                        .try_into()
                        .map_err(|_| "stored KYB point is malformed".to_string())?;
                    CompressedRistretto(raw)
                        .decompress()
                        .ok_or_else(|| "stored KYB point is not canonical".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?,
            issuer: ed25519_dalek::VerifyingKey::from_bytes(&issuer)
                .map_err(|_| "stored KYB issuer is not canonical".to_string())?,
            registry_id,
            signature: Signature::from_bytes(&signature),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LifecycleState {
    version: u8,
    generation: u64,
    entities: BTreeMap<String, EntityRecord>,
    appeals: BTreeMap<String, AppealRecord>,
    registries: BTreeMap<String, StoredRegistry>,
    events: Vec<AuditEvent>,
}

struct LifecycleStore {
    path: PathBuf,
    passphrase: Vec<u8>,
}

impl LifecycleStore {
    fn read_unlocked(&self) -> Result<LifecycleState, String> {
        let metadata = self.path.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("KYB lifecycle state must be a private regular file".into());
        }
        let mut raw = Vec::new();
        File::open(&self.path)
            .and_then(|mut file| file.read_to_end(&mut raw))
            .map_err(|error| error.to_string())?;
        let minimum = MAGIC.len() + SALT_BYTES + NONCE_BYTES + 16;
        if raw.len() < minimum || raw.get(..MAGIC.len()) != Some(MAGIC) {
            return Err("not an encrypted QOMM KYB lifecycle state".into());
        }
        let mut at = MAGIC.len();
        let salt = &raw[at..at + SALT_BYTES];
        at += SALT_BYTES;
        let nonce: &[u8; NONCE_BYTES] = raw[at..at + NONCE_BYTES]
            .try_into()
            .expect("fixed KYB nonce");
        at += NONCE_BYTES;
        let clear = decrypt_authenticated(
            &derive_secret_key(&self.passphrase, salt)?,
            nonce,
            AAD,
            &raw[at..],
        )?;
        let state: LifecycleState = serde_json::from_slice(&clear)
            .map_err(|_| "KYB lifecycle authentication failed".to_string())?;
        if state.version != 1 {
            return Err("unsupported KYB lifecycle state version".into());
        }
        Ok(state)
    }

    fn write_unlocked(&self, state: &LifecycleState) -> Result<(), String> {
        let mut salt = [0_u8; SALT_BYTES];
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let clear = serde_json::to_vec(state).map_err(|error| error.to_string())?;
        let encrypted = encrypt_authenticated(
            &derive_secret_key(&self.passphrase, &salt)?,
            &nonce,
            AAD,
            &clear,
        )?;
        let mut payload =
            Vec::with_capacity(MAGIC.len() + SALT_BYTES + NONCE_BYTES + encrypted.len());
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&encrypted);
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let temp = parent.join(format!(".qomm-kyb-{}.tmp", rand::random::<u64>()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|error| error.to_string())?;
            file.write_all(&payload)
                .and_then(|_| file.sync_all())
                .map_err(|error| error.to_string())?;
            fs::rename(&temp, &self.path).map_err(|error| error.to_string())?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| error.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

pub struct KybLifecycleService {
    store: LifecycleStore,
    signing: SigningKey,
    max_tier: u32,
}

impl KybLifecycleService {
    pub fn open(
        path: impl Into<PathBuf>,
        passphrase: &[u8],
        signing: SigningKey,
        max_tier: u32,
    ) -> Result<Self, String> {
        if passphrase.len() < 16 || max_tier == 0 {
            return Err("KYB lifecycle needs a strong passphrase and positive maximum tier".into());
        }
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let service = Self {
            store: LifecycleStore {
                path,
                passphrase: passphrase.to_vec(),
            },
            signing,
            max_tier,
        };
        let _lock = FileLock::acquire(&service.store.path)?;
        if !service.store.path.exists() {
            service.store.write_unlocked(&LifecycleState {
                version: 1,
                generation: 0,
                entities: BTreeMap::new(),
                appeals: BTreeMap::new(),
                registries: BTreeMap::new(),
                events: Vec::new(),
            })?;
        }
        let state = service.store.read_unlocked()?;
        service.verify_events(&state)?;
        Ok(service)
    }

    fn subject_digest(group: &str) -> String {
        hex::encode(
            Sha256::new()
                .chain_update(b"QOMM:KYB:CONTROL-GROUP:v1")
                .chain_update(group.as_bytes())
                .finalize(),
        )
    }

    fn append_event(
        &self,
        state: &mut LifecycleState,
        at: u64,
        kind: &str,
        subject: &str,
        payload: &[u8],
    ) -> Result<(), String> {
        let sequence = state.events.len() as u64 + 1;
        let previous = state
            .events
            .last()
            .map(|event| event.digest.clone())
            .unwrap_or_else(|| hex::encode([0_u8; 32]));
        let subject_digest = Self::subject_digest(subject);
        let payload_digest = hex::encode(Sha256::digest(payload));
        let digest = Sha256::new()
            .chain_update(EVENT_DOMAIN)
            .chain_update(sequence.to_be_bytes())
            .chain_update(at.to_be_bytes())
            .chain_update(kind.as_bytes())
            .chain_update(subject_digest.as_bytes())
            .chain_update(payload_digest.as_bytes())
            .chain_update(previous.as_bytes())
            .finalize();
        let signature = self.signing.sign(&digest);
        state.events.push(AuditEvent {
            sequence,
            at,
            kind: kind.into(),
            subject_digest,
            payload_digest,
            previous,
            digest: hex::encode(digest),
            signature: hex::encode(signature.to_bytes()),
        });
        Ok(())
    }

    fn verify_events(&self, state: &LifecycleState) -> Result<(), String> {
        let mut previous = hex::encode([0_u8; 32]);
        for (index, event) in state.events.iter().enumerate() {
            if event.sequence != index as u64 + 1 || event.previous != previous {
                return Err("KYB lifecycle audit chain is discontinuous".into());
            }
            let digest = Sha256::new()
                .chain_update(EVENT_DOMAIN)
                .chain_update(event.sequence.to_be_bytes())
                .chain_update(event.at.to_be_bytes())
                .chain_update(event.kind.as_bytes())
                .chain_update(event.subject_digest.as_bytes())
                .chain_update(event.payload_digest.as_bytes())
                .chain_update(event.previous.as_bytes())
                .finalize();
            if hex::encode(digest) != event.digest {
                return Err("KYB lifecycle audit digest is invalid".into());
            }
            let raw: [u8; 64] = hex::decode(&event.signature)
                .map_err(|_| "KYB lifecycle audit signature is malformed".to_string())?
                .try_into()
                .map_err(|_| "KYB lifecycle audit signature is malformed".to_string())?;
            self.signing
                .verifying_key()
                .verify(&digest, &Signature::from_bytes(&raw))
                .map_err(|_| "KYB lifecycle audit signature is invalid".to_string())?;
            previous = event.digest.clone();
        }
        Ok(())
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut LifecycleState) -> Result<T, String>,
    ) -> Result<T, String> {
        let _lock = FileLock::acquire(&self.store.path)?;
        let mut state = self.store.read_unlocked()?;
        self.verify_events(&state)?;
        let output = operation(&mut state)?;
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| "KYB lifecycle generation overflow".to_string())?;
        self.store.write_unlocked(&state)?;
        Ok(output)
    }

    pub fn issue<R: RngCore + CryptoRng>(
        &self,
        control_group_id: &str,
        legal_entity_reference: &[u8],
        attributes: BusinessAttributes,
        now: u64,
        rng: &mut R,
    ) -> Result<KybCredential, String> {
        let credential =
            KybCredential::issue(control_group_id, attributes.clone(), self.max_tier, rng)
                .map_err(str::to_string)?;
        let point = hex::encode(credential.public_point.compress().to_bytes());
        self.mutate(|state| {
            if state.entities.contains_key(control_group_id) {
                return Err("control group already exists in the KYB lifecycle".into());
            }
            let reference = hex::encode(Sha256::digest(legal_entity_reference));
            state.entities.insert(
                control_group_id.into(),
                EntityRecord {
                    legal_entity_ref_digest: reference,
                    public_point: point,
                    attributes,
                    revision: 1,
                    status: EntityStatus::Active,
                    merged_into: None,
                    updated_at: now,
                },
            );
            self.append_event(state, now, "issued", control_group_id, b"revision=1")
        })?;
        Ok(credential)
    }

    pub fn update<R: RngCore + CryptoRng>(
        &self,
        control_group_id: &str,
        attributes: BusinessAttributes,
        now: u64,
        rng: &mut R,
    ) -> Result<KybCredential, String> {
        let credential =
            KybCredential::issue(control_group_id, attributes.clone(), self.max_tier, rng)
                .map_err(str::to_string)?;
        let point = hex::encode(credential.public_point.compress().to_bytes());
        self.mutate(|state| {
            let revision = {
                let entity = state
                    .entities
                    .get_mut(control_group_id)
                    .ok_or_else(|| "unknown KYB control group".to_string())?;
                if entity.status != EntityStatus::Active {
                    return Err("only an active KYB control group can be updated".into());
                }
                entity.revision = entity
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| "KYB credential revision overflow".to_string())?;
                entity.public_point = point;
                entity.attributes = attributes;
                entity.updated_at = now;
                entity.revision
            };
            self.append_event(
                state,
                now,
                "updated",
                control_group_id,
                format!("revision={revision}").as_bytes(),
            )
        })?;
        Ok(credential)
    }

    pub fn revoke(&self, control_group_id: &str, reason: &[u8], now: u64) -> Result<(), String> {
        if reason.is_empty() {
            return Err("KYB revocation reason is required".into());
        }
        self.mutate(|state| {
            let entity = state
                .entities
                .get_mut(control_group_id)
                .ok_or_else(|| "unknown KYB control group".to_string())?;
            if entity.status != EntityStatus::Active {
                return Err("KYB control group is not active".into());
            }
            entity.status = EntityStatus::Revoked;
            entity.updated_at = now;
            self.append_event(state, now, "revoked", control_group_id, reason)
        })
    }

    pub fn merge<R: RngCore + CryptoRng>(
        &self,
        canonical_group: &str,
        absorbed_group: &str,
        now: u64,
        rng: &mut R,
    ) -> Result<KybCredential, String> {
        if canonical_group == absorbed_group {
            return Err("a KYB control group cannot merge into itself".into());
        }
        let (attributes, canonical_revision, absorbed_revision) = {
            let _lock = FileLock::acquire(&self.store.path)?;
            let state = self.store.read_unlocked()?;
            let canonical = state
                .entities
                .get(canonical_group)
                .ok_or_else(|| "unknown canonical KYB control group".to_string())?;
            let absorbed = state
                .entities
                .get(absorbed_group)
                .ok_or_else(|| "unknown absorbed KYB control group".to_string())?;
            if canonical.status != EntityStatus::Active || absorbed.status != EntityStatus::Active {
                return Err("both KYB control groups must be active before merge".into());
            }
            (
                canonical.attributes.clone(),
                canonical.revision,
                absorbed.revision,
            )
        };
        let credential =
            KybCredential::issue(canonical_group, attributes.clone(), self.max_tier, rng)
                .map_err(str::to_string)?;
        let point = hex::encode(credential.public_point.compress().to_bytes());
        self.mutate(|state| {
            {
                let canonical = state
                    .entities
                    .get_mut(canonical_group)
                    .ok_or_else(|| "unknown canonical KYB control group".to_string())?;
                if canonical.status != EntityStatus::Active
                    || canonical.revision != canonical_revision
                    || canonical.attributes != attributes
                {
                    return Err("canonical KYB control group changed during merge".into());
                }
                canonical.public_point = point;
                canonical.revision = canonical
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| "KYB credential revision overflow".to_string())?;
                canonical.updated_at = now;
            }
            {
                let absorbed = state
                    .entities
                    .get_mut(absorbed_group)
                    .ok_or_else(|| "unknown absorbed KYB control group".to_string())?;
                if absorbed.status != EntityStatus::Active || absorbed.revision != absorbed_revision
                {
                    return Err("absorbed KYB control group changed during merge".into());
                }
                absorbed.status = EntityStatus::Merged;
                absorbed.merged_into = Some(canonical_group.into());
                absorbed.updated_at = now;
            }
            self.append_event(
                state,
                now,
                "merged",
                absorbed_group,
                Self::subject_digest(canonical_group).as_bytes(),
            )
        })?;
        Ok(credential)
    }

    pub fn open_appeal(
        &self,
        control_group_id: &str,
        reason: &[u8],
        now: u64,
    ) -> Result<[u8; 32], String> {
        if reason.is_empty() {
            return Err("KYB appeal reason is required".into());
        }
        let case_id: [u8; 32] = Sha256::new()
            .chain_update(b"QOMM:KYB:APPEAL:v1")
            .chain_update(control_group_id.as_bytes())
            .chain_update(now.to_be_bytes())
            .chain_update(Sha256::digest(reason))
            .finalize()
            .into();
        self.mutate(|state| {
            if !state.entities.contains_key(control_group_id) {
                return Err("unknown KYB control group".into());
            }
            let key = hex::encode(case_id);
            if state.appeals.contains_key(&key) {
                return Err("KYB appeal already exists".into());
            }
            state.appeals.insert(
                key,
                AppealRecord {
                    control_group_id: control_group_id.into(),
                    reason_digest: hex::encode(Sha256::digest(reason)),
                    opened_at: now,
                    resolved_at: None,
                    status: AppealStatus::Pending,
                },
            );
            self.append_event(state, now, "appeal_opened", control_group_id, &case_id)
        })?;
        Ok(case_id)
    }

    pub fn resolve_appeal<R: RngCore + CryptoRng>(
        &self,
        case_id: [u8; 32],
        reinstate: bool,
        now: u64,
        rng: &mut R,
    ) -> Result<Option<KybCredential>, String> {
        let key = hex::encode(case_id);
        let (group, attributes, entity_revision, entity_status) = {
            let _lock = FileLock::acquire(&self.store.path)?;
            let state = self.store.read_unlocked()?;
            let appeal = state
                .appeals
                .get(&key)
                .ok_or_else(|| "unknown KYB appeal".to_string())?;
            if appeal.status != AppealStatus::Pending {
                return Err("KYB appeal was already resolved".into());
            }
            let entity = state
                .entities
                .get(&appeal.control_group_id)
                .ok_or_else(|| "appealed KYB entity is absent".to_string())?;
            (
                appeal.control_group_id.clone(),
                entity.attributes.clone(),
                entity.revision,
                entity.status.clone(),
            )
        };
        let credential = if reinstate {
            Some(
                KybCredential::issue(&group, attributes.clone(), self.max_tier, rng)
                    .map_err(str::to_string)?,
            )
        } else {
            None
        };
        let point = credential
            .as_ref()
            .map(|value| hex::encode(value.public_point.compress().to_bytes()));
        self.mutate(|state| {
            {
                let appeal = state
                    .appeals
                    .get_mut(&key)
                    .ok_or_else(|| "unknown KYB appeal".to_string())?;
                if appeal.status != AppealStatus::Pending {
                    return Err("KYB appeal changed during resolution".into());
                }
                appeal.status = if reinstate {
                    AppealStatus::Reinstated
                } else {
                    AppealStatus::Upheld
                };
                appeal.resolved_at = Some(now);
            }
            if let Some(point) = point {
                let entity = state
                    .entities
                    .get_mut(&group)
                    .ok_or_else(|| "appealed KYB entity is absent".to_string())?;
                if entity.revision != entity_revision
                    || entity.status != entity_status
                    || entity.attributes != attributes
                {
                    return Err("KYB entity changed during appeal resolution".into());
                }
                entity.status = EntityStatus::Active;
                entity.merged_into = None;
                entity.public_point = point;
                entity.revision = entity
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| "KYB credential revision overflow".to_string())?;
                entity.updated_at = now;
            }
            self.append_event(
                state,
                now,
                if reinstate {
                    "appeal_reinstated"
                } else {
                    "appeal_upheld"
                },
                &group,
                &case_id,
            )
        })?;
        Ok(credential)
    }

    pub fn publish_registry(
        &self,
        cohort: &str,
        registry_epoch: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<SignedCohortRegistry, String> {
        if expires_at <= now {
            return Err("KYB registry must expire in the future".into());
        }
        self.mutate(|state| {
            if state
                .registries
                .get(cohort)
                .is_some_and(|registry| registry.registry_epoch >= registry_epoch)
            {
                return Err("KYB registry epoch must increase".into());
            }
            let points = state
                .entities
                .values()
                .filter(|entity| {
                    entity.status == EntityStatus::Active
                        && entity
                            .attributes
                            .cohorts(self.max_tier)
                            .contains(&cohort.to_string())
                })
                .map(|entity| {
                    let raw: [u8; 32] = hex::decode(&entity.public_point)
                        .map_err(|_| "stored KYB entity point is malformed".to_string())?
                        .try_into()
                        .map_err(|_| "stored KYB entity point is malformed".to_string())?;
                    CompressedRistretto(raw)
                        .decompress()
                        .ok_or_else(|| "stored KYB entity point is not canonical".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let registry = SignedCohortRegistry::issue(
                cohort,
                registry_epoch,
                expires_at,
                points,
                &self.signing,
            )
            .map_err(str::to_string)?;
            state
                .registries
                .insert(cohort.into(), StoredRegistry::from_registry(&registry));
            self.append_event(
                state,
                now,
                "registry_published",
                cohort,
                &registry.registry_id,
            )?;
            Ok(registry)
        })
    }

    pub fn latest_registry(
        &self,
        cohort: &str,
        now: u64,
    ) -> Result<Option<SignedCohortRegistry>, String> {
        let _lock = FileLock::acquire(&self.store.path)?;
        let state = self.store.read_unlocked()?;
        self.verify_events(&state)?;
        state
            .registries
            .get(cohort)
            .map(StoredRegistry::registry)
            .transpose()?
            .map(|registry| {
                verify_registry(&registry, &self.signing.verifying_key(), now)
                    .map_err(|error| format!("cached KYB registry is invalid: {error:?}"))?;
                Ok(registry)
            })
            .transpose()
    }

    pub fn audit_event_count(&self) -> Result<usize, String> {
        let _lock = FileLock::acquire(&self.store.path)?;
        let state = self.store.read_unlocked()?;
        self.verify_events(&state)?;
        Ok(state.events.len())
    }
}
