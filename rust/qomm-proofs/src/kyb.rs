//! Anonymous legal-entity credentials with entity-level limits.
//!
//! The design protects a legal entity, not a wallet, and two things follow.
//!
//! The protected unit has to survive an entity opening more wallets, so a limit
//! is keyed on a *scope nullifier* derived from the entity secret. Every wallet
//! of one entity produces the same nullifier inside a scope, so counting is
//! exact, while the nullifier says nothing about which entity it is and does
//! not carry across scopes.
//!
//! Business attributes — jurisdiction, entity type, collateral tier — have to
//! be usable as gates without being revealed. Proving a predicate about a
//! hidden registry entry inside the membership proof would cost a proof per
//! entry. Cohort registries avoid that: the issuer publishes one signed
//! registry per satisfied predicate and enrols an entity in every cohort it
//! qualifies for, so membership in the "tier at least 3" registry *is* the
//! attribute proof and costs the prover nothing extra.
//!
//! The trade is explicit. The anonymity set becomes the cohort rather than the
//! whole population, and an observer who sees one scope nullifier in two cohort
//! presentations learns those cohorts share an entity. Re-randomisable
//! credentials avoid both at the cost of a pairing-based implementation.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qomm_zk::or_dleq::{self, Proof, Statement};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BusinessAttributes {
    pub jurisdiction: String,
    pub entity_type: String,
    /// Monotone: a higher tier satisfies every lower gate.
    pub collateral_tier: u32,
}

pub fn cohort_id(jurisdiction: &str, entity_type: &str, min_tier: u32) -> String {
    format!("{jurisdiction}/{entity_type}/tier>={min_tier}")
}

impl BusinessAttributes {
    /// Every cohort this entity qualifies for, lower tiers included.
    pub fn cohorts(&self, max_tier: u32) -> Vec<String> {
        (1..=self.collateral_tier.min(max_tier))
            .map(|tier| cohort_id(&self.jurisdiction, &self.entity_type, tier))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct KybCredential {
    pub control_group_id: String,
    secret: Scalar,
    pub public_point: RistrettoPoint,
    pub attributes: BusinessAttributes,
    pub cohorts: Vec<String>,
}

impl KybCredential {
    /// Issue a fresh unlinkable credential. Persistent issuer services retain
    /// only the public point and rotate this secret on update/reinstatement.
    pub fn issue<R: RngCore + CryptoRng>(
        control_group_id: &str,
        attributes: BusinessAttributes,
        max_tier: u32,
        rng: &mut R,
    ) -> Result<Self, &'static str> {
        if control_group_id.trim().is_empty() || max_tier == 0 {
            return Err("control group and maximum tier are required");
        }
        let secret = Scalar::random(rng);
        Ok(Self {
            control_group_id: control_group_id.to_string(),
            secret,
            public_point: RISTRETTO_BASEPOINT_POINT * secret,
            cohorts: attributes.cohorts(max_tier),
            attributes,
        })
    }

    /// Reconstruct a credential inside the legal entity's protected service.
    ///
    /// The scalar is expected to come from an encrypted key store or HSM.  It
    /// is never part of a presentation and must not be sent to the venue.  The
    /// constructor exists so a participant service can survive restarts while
    /// keeping the same venue-scoped nullifier and facility limit.
    pub fn from_secret_scalar(
        control_group_id: &str,
        attributes: BusinessAttributes,
        max_tier: u32,
        secret: Scalar,
    ) -> Result<Self, &'static str> {
        if control_group_id.trim().is_empty() || max_tier == 0 || secret == Scalar::ZERO {
            return Err("control group, maximum tier, and non-zero secret are required");
        }
        Ok(Self {
            control_group_id: control_group_id.to_string(),
            public_point: RISTRETTO_BASEPOINT_POINT * secret,
            secret,
            cohorts: attributes.cohorts(max_tier),
            attributes,
        })
    }

    /// What the venue counts against. Equal across an entity's wallets,
    /// unrelated across scopes.
    pub fn scope_nullifier(&self, scope: &[u8]) -> RistrettoPoint {
        or_dleq::nullifier(scope, &self.secret)
    }
}

#[derive(Clone, Debug)]
pub struct SignedCohortRegistry {
    pub cohort: String,
    pub registry_epoch: u64,
    pub expires_at: u64,
    pub points: Vec<RistrettoPoint>,
    pub issuer: VerifyingKey,
    pub registry_id: [u8; 32],
    pub signature: Signature,
}

impl SignedCohortRegistry {
    fn body(
        cohort: &str,
        epoch: u64,
        expires_at: u64,
        points: &[RistrettoPoint],
        issuer: &VerifyingKey,
    ) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"qomm:kyb-registry:");
        h.update(cohort.as_bytes());
        h.update(epoch.to_be_bytes());
        h.update(expires_at.to_be_bytes());
        h.update((points.len() as u64).to_be_bytes());
        for point in points {
            h.update(point.compress().as_bytes());
        }
        h.update(issuer.as_bytes());
        h.finalize().to_vec()
    }

    /// Sign one canonical cohort registry from lifecycle-managed public
    /// credential points. Entity secrets are neither required nor retained.
    pub fn issue(
        cohort: &str,
        registry_epoch: u64,
        expires_at: u64,
        mut points: Vec<RistrettoPoint>,
        signing: &SigningKey,
    ) -> Result<Self, &'static str> {
        if cohort.trim().is_empty() || registry_epoch == 0 || expires_at == 0 || points.is_empty() {
            return Err("cohort registry is incomplete");
        }
        points.sort_by_key(|point| point.compress().to_bytes());
        if points
            .windows(2)
            .any(|pair| pair[0].compress() == pair[1].compress())
        {
            return Err("cohort registry contains duplicate entities");
        }
        let issuer = signing.verifying_key();
        let body = Self::body(cohort, registry_epoch, expires_at, &points, &issuer);
        let registry_id: [u8; 32] = body
            .try_into()
            .map_err(|_| "cohort registry digest is malformed")?;
        let signature = signing.sign(&registry_id);
        Ok(Self {
            cohort: cohort.to_string(),
            registry_epoch,
            expires_at,
            points,
            issuer,
            registry_id,
            signature,
        })
    }
}

#[derive(Clone, Debug)]
pub struct KybPresentation {
    pub cohort: String,
    pub registry_id: [u8; 32],
    pub scope: Vec<u8>,
    pub context_hash: [u8; 32],
    pub proof: Proof,
}

impl KybPresentation {
    /// Stable commitment used by a signed RFQ or Maker policy.  The verifier
    /// still checks the full presentation against the live registry; this
    /// digest only prevents substituting another valid legal entity after the
    /// mandate was signed.
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"QOMM:KYB:PRESENTATION:v1");
        hash.update((self.cohort.len() as u32).to_be_bytes());
        hash.update(self.cohort.as_bytes());
        hash.update(self.registry_id);
        hash.update((self.scope.len() as u32).to_be_bytes());
        hash.update(&self.scope);
        hash.update(self.context_hash);
        hash.update(self.proof.nullifier.compress().as_bytes());
        hash.update((self.proof.challenges.len() as u32).to_be_bytes());
        for challenge in &self.proof.challenges {
            hash.update(challenge.as_bytes());
        }
        hash.update((self.proof.responses.len() as u32).to_be_bytes());
        for response in &self.proof.responses {
            hash.update(response.as_bytes());
        }
        hash.finalize().into()
    }

    /// Stable authorization binding for a long-lived mandate in one venue
    /// scope. The membership proof itself is deliberately re-randomized on
    /// every presentation, so its full transcript digest must never be used
    /// as a durable facility or reserve identifier. This binding keeps the
    /// cohort, registry, scope, context and scope nullifier, while excluding
    /// one-use proof challenges and responses.
    pub fn binding_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"QOMM:KYB:SCOPE-BINDING:v1");
        hash.update((self.cohort.len() as u32).to_be_bytes());
        hash.update(self.cohort.as_bytes());
        hash.update(self.registry_id);
        hash.update((self.scope.len() as u32).to_be_bytes());
        hash.update(&self.scope);
        hash.update(self.context_hash);
        hash.update(self.proof.nullifier.compress().as_bytes());
        hash.finalize().into()
    }

    /// Pseudonymous facility beneficiary for one venue scope.  It is equal for
    /// wallets controlled by the same legal entity inside that scope and does
    /// not reveal the registry entry that entity proved.
    pub fn entity_commitment(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"QOMM:KYB:FACILITY-ENTITY:v1")
            .chain_update(self.proof.nullifier.compress().as_bytes())
            .finalize()
            .into()
    }
}

pub struct KybIssuer {
    signing: SigningKey,
    pub max_tier: u32,
    enrolled: HashMap<String, KybCredential>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    NotFromTrustedIssuer,
    Expired,
    DuplicateEntries,
    RegistryIdMismatch,
    BadIssuerSignature,
    WrongCohort,
    WrongRegistryEpoch,
    WrongScopeOrContext,
    MembershipProofFailed,
}

impl KybIssuer {
    pub fn new<R: RngCore + CryptoRng>(max_tier: u32, rng: &mut R) -> Self {
        KybIssuer {
            signing: SigningKey::generate(rng),
            max_tier,
            enrolled: HashMap::new(),
        }
    }

    /// Build an issuer around a governance/HSM-managed signing key. Random
    /// construction remains convenient for tests, while deployed verifiers
    /// can pin a key that survives process restarts instead of trusting a key
    /// carried by the registry it signs.
    pub fn with_signing_key(max_tier: u32, signing: SigningKey) -> Result<Self, &'static str> {
        if max_tier == 0 {
            return Err("maximum tier must be positive");
        }
        Ok(Self {
            signing,
            max_tier,
            enrolled: HashMap::new(),
        })
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn enroll<R: RngCore + CryptoRng>(
        &mut self,
        control_group_id: &str,
        attributes: BusinessAttributes,
        rng: &mut R,
    ) -> Result<KybCredential, &'static str> {
        if self.enrolled.contains_key(control_group_id) {
            return Err("control group already enrolled");
        }
        let credential = KybCredential::issue(control_group_id, attributes, self.max_tier, rng)?;
        self.enrolled
            .insert(control_group_id.to_string(), credential.clone());
        Ok(credential)
    }

    pub fn publish(
        &self,
        cohort: &str,
        registry_epoch: u64,
        expires_at: u64,
    ) -> Result<SignedCohortRegistry, &'static str> {
        let points: Vec<RistrettoPoint> = self
            .enrolled
            .values()
            .filter(|c| c.cohorts.iter().any(|k| k == cohort))
            .map(|c| c.public_point)
            .collect();
        if points.is_empty() {
            return Err("no entity qualifies for this cohort");
        }
        SignedCohortRegistry::issue(cohort, registry_epoch, expires_at, points, &self.signing)
    }

    /// Attribution hook: a bad policy stays traceable to an enrolled entity.
    pub fn sign_policy_digest(&self, digest: &[u8]) -> Vec<u8> {
        self.signing.sign(digest).to_bytes().to_vec()
    }
}

pub fn verify_registry(
    registry: &SignedCohortRegistry,
    trusted: &VerifyingKey,
    now: u64,
) -> Result<(), Invalid> {
    if registry.issuer != *trusted {
        return Err(Invalid::NotFromTrustedIssuer);
    }
    if registry.expires_at <= now {
        return Err(Invalid::Expired);
    }
    let mut seen: Vec<[u8; 32]> = registry
        .points
        .iter()
        .map(|p| p.compress().to_bytes())
        .collect();
    let before = seen.len();
    seen.sort_unstable();
    seen.dedup();
    if seen.len() != before {
        return Err(Invalid::DuplicateEntries);
    }
    let body = SignedCohortRegistry::body(
        &registry.cohort,
        registry.registry_epoch,
        registry.expires_at,
        &registry.points,
        &registry.issuer,
    );
    if body != registry.registry_id {
        return Err(Invalid::RegistryIdMismatch);
    }
    trusted
        .verify(&registry.registry_id, &registry.signature)
        .map_err(|_| Invalid::BadIssuerSignature)
}

pub fn context_hash(context: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"qomm:kyb-context:");
    h.update(context);
    h.finalize().into()
}

pub fn present<R: RngCore + CryptoRng>(
    credential: &KybCredential,
    registry: &SignedCohortRegistry,
    scope: &[u8],
    context: &[u8],
    rng: &mut R,
) -> Result<KybPresentation, &'static str> {
    if !credential.cohorts.contains(&registry.cohort) {
        return Err("credential does not qualify for this cohort");
    }
    let index = registry
        .points
        .iter()
        .position(|p| *p == credential.public_point)
        .ok_or("credential is not in this registry")?;
    let hash = context_hash(context);
    let statement = Statement {
        registry_id: &registry.registry_id,
        points: &registry.points,
        scope,
        context_hash: &hash,
    };
    let proof = or_dleq::prove(&statement, &credential.secret, index, rng)?;
    Ok(KybPresentation {
        cohort: registry.cohort.clone(),
        registry_id: registry.registry_id,
        scope: scope.to_vec(),
        context_hash: hash,
        proof,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_presentation(
    presentation: &KybPresentation,
    registry: &SignedCohortRegistry,
    trusted: &VerifyingKey,
    scope: &[u8],
    context: &[u8],
    now: u64,
    required_cohort: &str,
) -> Result<(), Invalid> {
    verify_registry(registry, trusted, now)?;
    if registry.cohort != required_cohort || presentation.cohort != required_cohort {
        return Err(Invalid::WrongCohort);
    }
    if presentation.registry_id != registry.registry_id {
        return Err(Invalid::WrongRegistryEpoch);
    }
    let hash = context_hash(context);
    if presentation.scope != scope || presentation.context_hash != hash {
        return Err(Invalid::WrongScopeOrContext);
    }
    let statement = Statement {
        registry_id: &registry.registry_id,
        points: &registry.points,
        scope,
        context_hash: &hash,
    };
    if !or_dleq::verify(&statement, &presentation.proof) {
        return Err(Invalid::MembershipProofFailed);
    }
    Ok(())
}

/// Per-entity caps the venue enforces, keyed on the scope nullifier.
#[derive(Clone, Copy, Debug)]
pub struct EntityLimits {
    pub max_requests: u64,
    pub max_probe_lots: u64,
    pub max_epsilon: f64,
}

impl Default for EntityLimits {
    fn default() -> Self {
        EntityLimits {
            max_requests: 60,
            max_probe_lots: 2_000,
            max_epsilon: 1.0,
        }
    }
}

/// Counts against the legal entity, not the wallet. The nullifier is identical
/// for every wallet the entity controls inside a scope, so opening more wallets
/// buys no extra allowance --- which is the whole reason the limit lives here
/// rather than on an address.
#[derive(Default)]
pub struct EntityRateLimiter {
    pub limits: EntityLimits,
    requests: HashMap<([u8; 32], u64), u64>,
    lots: HashMap<([u8; 32], u64), u64>,
    epsilon: HashMap<([u8; 32], u64), f64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    RequestCap,
    ProbeVolumeCap,
    PrivacyBudget,
}

#[derive(Debug, PartialEq)]
pub struct Usage {
    pub requests: u64,
    pub lots: u64,
    pub epsilon: f64,
}

impl EntityRateLimiter {
    pub fn new(limits: EntityLimits) -> Self {
        EntityRateLimiter {
            limits,
            ..Default::default()
        }
    }

    fn key(nullifier: &RistrettoPoint, epoch: u64) -> ([u8; 32], u64) {
        (nullifier.compress().to_bytes(), epoch)
    }

    pub fn allow_request(
        &mut self,
        nullifier: &RistrettoPoint,
        epoch: u64,
        lots: u64,
    ) -> Result<(), Refused> {
        let key = Self::key(nullifier, epoch);
        if self.requests.get(&key).copied().unwrap_or(0) + 1 > self.limits.max_requests {
            return Err(Refused::RequestCap);
        }
        if self.lots.get(&key).copied().unwrap_or(0) + lots > self.limits.max_probe_lots {
            return Err(Refused::ProbeVolumeCap);
        }
        *self.requests.entry(key).or_insert(0) += 1;
        *self.lots.entry(key).or_insert(0) += lots;
        Ok(())
    }

    pub fn spend_epsilon(
        &mut self,
        nullifier: &RistrettoPoint,
        epoch: u64,
        epsilon: f64,
    ) -> Result<(), Refused> {
        let key = Self::key(nullifier, epoch);
        let spent = self.epsilon.get(&key).copied().unwrap_or(0.0);
        if spent + epsilon > self.limits.max_epsilon + 1e-12 {
            return Err(Refused::PrivacyBudget);
        }
        *self.epsilon.entry(key).or_insert(0.0) += epsilon;
        Ok(())
    }

    pub fn usage(&self, nullifier: &RistrettoPoint, epoch: u64) -> Usage {
        let key = Self::key(nullifier, epoch);
        Usage {
            requests: self.requests.get(&key).copied().unwrap_or(0),
            lots: self.lots.get(&key).copied().unwrap_or(0),
            epsilon: self.epsilon.get(&key).copied().unwrap_or(0.0),
        }
    }
}
