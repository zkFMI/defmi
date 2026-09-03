//! Handing an auditor one slice of a wallet, and being honest about what that is.
//!
//! `notes.rs` splits a wallet into a view key and a spend key and says the view
//! key could be handed to an auditor. It could, and that is all it could: the
//! key is one key, so handing it over gives the whole history of that wallet,
//! in every instrument, for every period, permanently. There is no scope and no
//! way back.
//!
//! **The scoping does not go in the key. It goes in the address.** A wallet is
//! a pair of seeds; a scope --- an instrument, a quarter, a mandate --- derives
//! a fresh pair of scalars by hashing, and therefore a fresh address. Notes sent
//! there are found by that scope's view key and by nothing else, and the
//! derivation is one way, so a scope's key says nothing about the seed or about
//! a sibling scope.
//!
//! ```text
//! view_s  = H("view"  || seed_v || scope)      the auditor gets this
//! spend_s = H("spend" || seed_s || scope)      it does not
//! address = (G * view_s, G * spend_s)          both halves are public
//! ```
//!
//! Nothing here is new cryptography, deliberately: the note construction is
//! unchanged, the scan is unchanged, and what changes is which address a payer
//! is told to use. Which means it also works with a counterparty that has
//! already implemented the old thing.
//!
//! # Three things it does not do
//!
//! **A grant cannot be taken back.** Whoever holds a scope's key can read every
//! note ever sent to that address and every one that ever will be. An expiry
//! stops a party that chooses to be stopped and nothing else. What actually
//! revokes is moving to the next scope, because the next scope is a different
//! address --- revocation is address management, not a message.
//!
//! **A view key is incoming only, and closing that is not a matter of effort.**
//! It finds what arrived and cannot see what the wallet spent. The obvious fix
//! --- hand the auditor the serials too --- does not work, and the reason is
//! worth following because it is a property of the construction rather than an
//! omission.
//!
//! Spending a note needs the serial `S` **and** the note's blinding `r`, and a
//! view key recovers `r` by scanning. So a party holding both the view key and
//! the serials can spend, and giving an auditor outflows on top of inflows is
//! giving it the wallet. Verifying an outflow list without the view key is no
//! better: a serial belongs to an address exactly when `S - H(E^a) = b`, and
//! the hash puts that outside what a sigma protocol can prove --- establishing
//! it needs a general-purpose proof system, which this stack deliberately does
//! not use.
//!
//! What is left is [`SpendDisclosure`]: the wallet **signs** what it spent, and
//! anyone can check the signature and check that each serial is in the ledger's
//! spent set. That is attribution, not verification --- a wallet can leave a
//! spend out and nothing here catches it --- and it confers no ability to
//! spend, which is why it is the disclosure that can exist. An auditor holding
//! one of these plus a view key has the wallet, so the two are not meant to go
//! to the same party and `SpendDisclosure` says so where it is built.
//!
//! **Scoping is only as fine as the payers cooperate.** A scope exists because
//! counterparties were told to pay to that address; one who uses last quarter's
//! address puts the note in last quarter's scope and nothing in the protocol
//! stops them. That is an operational control wearing a cryptographic coat, and
//! it is worth knowing which it is.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::notes::{Address, NoteLedger, ViewKey, Wallet};

pub const VIEW_DOMAIN: &[u8] = b"qomm:defmi:view:v1";

/// One scope's scalar. One way, so a scope reveals neither seed nor sibling.
pub fn derive(seed: &[u8], role: &[u8], scope: &str) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(VIEW_DOMAIN);
    hasher.update(b":");
    hasher.update(role);
    hasher.update(b":");
    for part in [seed, scope.as_bytes()] {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

/// One scope handed to one named party, signed by the wallet that owns it.
///
/// The grantee is named and the grant is signed so that a key found somewhere
/// it should not be can be traced to the grant that produced it. That is
/// attribution, not prevention, and it is the same trade the dealt shares make.
pub struct ViewingGrant {
    pub scope: String,
    pub grantee: String,
    pub address: Address,
    pub view_key: ViewKey,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Option<Signature>,
}

impl ViewingGrant {
    pub fn body(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(VIEW_DOMAIN);
        hasher.update(b":grant:");
        for part in [self.scope.as_bytes(), self.grantee.as_bytes()] {
            hasher.update((part.len() as u32).to_be_bytes());
            hasher.update(part);
        }
        hasher.update(self.address.view.compress().as_bytes());
        hasher.update(self.address.spend.compress().as_bytes());
        hasher.update(self.issued_at.to_be_bytes());
        hasher.update(self.expires_at.to_be_bytes());
        hasher.finalize().into()
    }
}

/// A wallet that can hand out one slice of itself at a time.
///
/// The seeds never leave. A scope is derived from them, so the wallet can
/// reproduce any scope it has ever granted --- which is what lets it keep
/// spending notes it has given an auditor the ability to read.
pub struct ScopedWallet {
    view_seed: [u8; 32],
    spend_seed: [u8; 32],
    identity: SigningKey,
}

impl ScopedWallet {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut view_seed = [0u8; 32];
        let mut spend_seed = [0u8; 32];
        rng.fill_bytes(&mut view_seed);
        rng.fill_bytes(&mut spend_seed);
        ScopedWallet {
            view_seed,
            spend_seed,
            identity: SigningKey::generate(rng),
        }
    }

    pub fn from_seeds(view_seed: [u8; 32], spend_seed: [u8; 32], identity: SigningKey) -> Self {
        ScopedWallet {
            view_seed,
            spend_seed,
            identity,
        }
    }

    pub fn public_identity(&self) -> VerifyingKey {
        self.identity.verifying_key()
    }

    /// The full wallet for one scope. This is what spends.
    pub fn wallet(&self, scope: &str) -> Wallet {
        Wallet::from_parts(
            derive(&self.view_seed, b"view", scope),
            derive(&self.spend_seed, b"spend", scope),
        )
    }

    pub fn address(&self, scope: &str) -> Address {
        self.wallet(scope).address
    }

    /// Hand out the ability to read one scope, and sign that it was handed out.
    pub fn grant(&self, scope: &str, grantee: &str, issued_at: u64, days: u64) -> ViewingGrant {
        self.grant_until(
            scope,
            grantee,
            issued_at,
            issued_at + days.saturating_mul(86_400),
        )
    }

    /// The same, to an exact second rather than to a whole day.
    ///
    /// `grant_current` used to convert the remaining time to days, rounding
    /// *up*, and then multiply back --- so a grant meant to expire with its
    /// period outlived it by up to 86,399 seconds. That is exactly the state
    /// the doc above calls "current for a scope nothing is being paid into,
    /// which looks like access and is not".
    pub fn grant_until(
        &self,
        scope: &str,
        grantee: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> ViewingGrant {
        let view = derive(&self.view_seed, b"view", scope);
        let spend = derive(&self.spend_seed, b"spend", scope);
        let mut grant = ViewingGrant {
            scope: scope.to_string(),
            grantee: grantee.to_string(),
            address: Address {
                view: G * view,
                spend: G * spend,
            },
            view_key: ViewKey::new(view),
            issued_at,
            expires_at,
            signature: None,
        };
        grant.signature = Some(self.identity.sign(&grant.body()));
        grant
    }
}

/// Whether this grant is what it says, and still current.
///
/// Current is a statement about policy and not about capability. A party
/// holding the key can read whatever the key reads whether or not this returns
/// `Ok`; what refusing buys is that a party which *wants* to stay inside its
/// mandate has something to check against, and that a party which does not can
/// be shown to have gone outside it.
pub fn check_grant(
    grant: &ViewingGrant,
    owner: &VerifyingKey,
    now: u64,
) -> Result<(), &'static str> {
    let signature = grant
        .signature
        .as_ref()
        .ok_or("an unsigned grant is a key somebody wrote down")?;
    owner
        .verify(&grant.body(), signature)
        .map_err(|_| "not signed by that wallet")?;
    if grant.view_key.address_view() != grant.address.view {
        return Err("the key does not open the address it names");
    }
    if now < grant.issued_at {
        return Err("the grant has not begun");
    }
    if now >= grant.expires_at {
        return Err(
            "the grant has expired --- which stops a party that chooses \
                    to be stopped, and nothing else",
        );
    }
    Ok(())
}

/// Every note in the pool addressed to this scope, and their amounts.
pub fn scan_scope(
    ledger: &NoteLedger,
    grant: &ViewingGrant,
    asset_key: &Pedersen,
) -> Vec<(usize, u64, Scalar)> {
    ledger.scan_view(&grant.view_key, &grant.address, asset_key)
}

/// What the scope holds, for an auditor that has to put a number in a report.
pub fn total_seen(found: &[(usize, u64, Scalar)]) -> u64 {
    found.iter().map(|(_, value, _)| value).sum()
}

/// The commitments for one scope, so an auditor can reconcile it against a
/// figure it was given without opening any single note.
///
/// This is the join between the two modules: a scope is a set of positions, and
/// `reconcile` is what turns a set of positions into agreement with a number.
pub fn scope_commitments(
    ledger: &NoteLedger,
    grant: &ViewingGrant,
    asset_key: &Pedersen,
) -> (Vec<RistrettoPoint>, Vec<Scalar>, u64) {
    let found = scan_scope(ledger, grant, asset_key);
    let mut commitments = Vec::with_capacity(found.len());
    let mut blindings = Vec::with_capacity(found.len());
    let mut total = 0u64;
    for (_, value, blinding) in &found {
        commitments.push(asset_key.commit_u64(*value, blinding));
        blindings.push(*blinding);
        total += value;
    }
    (commitments, blindings, total)
}

// --- outflows, which are a different disclosure and a weaker one -----------

/// What a wallet says it spent in one scope, signed rather than proved.
///
/// **This does not go to the holder of the scope's view key.** Spending a note
/// needs the serial and the note's blinding, and a view key recovers the
/// blinding by scanning --- so a party with both can spend. The two disclosures
/// are for different parties on purpose, and [`conflicts_with`] is the check
/// that says when they are not.
///
/// What a holder can establish: that this wallet signed this list, and that
/// every serial on it is in the ledger's spent set. What nobody can establish
/// is that the list is complete. A wallet can leave a spend out and the
/// construction cannot tell --- which is the same shape as a clearing house
/// omitting a trade, and is stated in the same place rather than left to be
/// discovered.
pub struct SpendDisclosure {
    pub scope: String,
    pub grantee: String,
    pub serials: Vec<Scalar>,
    pub issued_at: u64,
    pub signature: Option<Signature>,
}

impl SpendDisclosure {
    pub fn body(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(VIEW_DOMAIN);
        hasher.update(b":spent:");
        for part in [self.scope.as_bytes(), self.grantee.as_bytes()] {
            hasher.update((part.len() as u32).to_be_bytes());
            hasher.update(part);
        }
        hasher.update((self.serials.len() as u32).to_be_bytes());
        for serial in &self.serials {
            hasher.update(serial.to_bytes());
        }
        hasher.update(self.issued_at.to_be_bytes());
        hasher.finalize().into()
    }
}

impl ScopedWallet {
    /// Say what one scope spent, and sign it.
    ///
    /// The serials come from the wallet's own scan, so producing this needs the
    /// spend key --- which is the point: nobody else can produce it, and the
    /// signature is what makes it worth anything.
    pub fn disclose_spends(
        &self,
        ledger: &NoteLedger,
        scope: &str,
        grantee: &str,
        asset_key: &Pedersen,
        issued_at: u64,
    ) -> SpendDisclosure {
        let wallet = self.wallet(scope);
        let serials = ledger
            .scan(&wallet, asset_key)
            .into_iter()
            .map(|(_, opening)| opening.serial)
            .filter(|serial| ledger.is_spent(serial))
            .collect();
        let mut disclosure = SpendDisclosure {
            scope: scope.to_string(),
            grantee: grantee.to_string(),
            serials,
            issued_at,
            signature: None,
        };
        disclosure.signature = Some(self.identity.sign(&disclosure.body()));
        disclosure
    }

    /// Sign a disclosure somebody assembled by hand. Only the tests need this,
    /// and they need it to say what a *dishonest* disclosure looks like.
    pub fn sign_disclosure(&self, disclosure: &SpendDisclosure) -> Signature {
        self.identity.sign(&disclosure.body())
    }
}

/// That this wallet signed this list, and that the ledger agrees each was spent.
///
/// Completeness is not established and cannot be. The return value says how
/// many serials the ledger has no record of, because a list naming a spend that
/// never happened is a different failure from one that leaves a spend out, and
/// only the first is visible here.
pub fn check_spend_disclosure(
    disclosure: &SpendDisclosure,
    owner: &VerifyingKey,
    ledger: &NoteLedger,
) -> Result<usize, &'static str> {
    let signature = disclosure
        .signature
        .as_ref()
        .ok_or("an unsigned disclosure is a list somebody typed")?;
    owner
        .verify(&disclosure.body(), signature)
        .map_err(|_| "not signed by that wallet")?;
    let unknown = disclosure
        .serials
        .iter()
        .filter(|serial| !ledger.is_spent(serial))
        .count();
    if unknown > 0 {
        return Err("the list names a spend the ledger has no record of");
    }
    Ok(disclosure.serials.len())
}

/// Whether handing both of these to one party would hand it the wallet.
///
/// It would, whenever they are for the same scope: the view key recovers each
/// note's blinding and the disclosure supplies the serials, and a spend needs
/// exactly those two. Written as a function rather than a warning in a comment
/// because it is the kind of thing an integration does by accident.
pub fn conflicts_with(grant: &ViewingGrant, disclosure: &SpendDisclosure) -> bool {
    grant.scope == disclosure.scope
}

// --- rolling a scope, which is what revocation actually is ------------------

/// A scope that moves on a schedule, so that revoking is an act somebody takes
/// rather than a discipline they keep.
///
/// The module says revocation is the next scope, and leaves it there. That is
/// true and it is not enough: a wallet that never rolls has granted forever
/// without deciding to, and a payer that is never told a new address keeps
/// paying into the old scope whatever the wallet intended. So the schedule is
/// an object --- what the current scope is, what address to publish, and when
/// it stops being current.
///
/// **It does not make an old key stop working.** Nothing can. What it does is
/// make the thing that *does* work --- moving --- something a caller can do on
/// a clock instead of remembering to.
#[derive(Clone)]
pub struct Rolling {
    pub name: String,
    /// Seconds a period lasts. A quarter is the usual unit for a mandate.
    ///
    /// Private because zero is not a period. Every instant would fall in the
    /// same scope --- the permanent scope this module exists to avoid --- and
    /// the division that finds the period would trap. The constructor refuses
    /// it, so `period_of` never has to decide what a scope means when there is
    /// no schedule.
    period: u64,
    pub epoch: u64,
}

impl Rolling {
    /// A schedule of `period` seconds counted from `epoch`.
    pub fn new(name: &str, period: u64, epoch: u64) -> Result<Self, &'static str> {
        if period == 0 {
            return Err("a rolling schedule needs a period; zero never rolls");
        }
        Ok(Rolling {
            name: name.to_string(),
            period,
            epoch,
        })
    }

    pub fn quarterly(name: &str, epoch: u64) -> Self {
        Rolling {
            name: name.to_string(),
            period: 90 * 86_400,
            epoch,
        }
    }

    /// Seconds a period lasts. Never zero.
    pub fn period(&self) -> u64 {
        self.period
    }

    pub fn period_of(&self, now: u64) -> u64 {
        now.saturating_sub(self.epoch) / self.period
    }

    /// The scope in force at `now`. Deterministic, so a payer and a payee
    /// derive the same one from the same clock.
    pub fn scope(&self, now: u64) -> String {
        format!("{}:{}", self.name, self.period_of(now))
    }

    /// When the current period stops being current.
    ///
    /// Saturating: a schedule whose end does not fit a `u64` ends at the end of
    /// the clock, which is the honest answer --- reporting a wrapped, earlier
    /// instant would expire a live grant.
    pub fn ends_at(&self, now: u64) -> u64 {
        self.period_of(now)
            .checked_add(1)
            .and_then(|n| n.checked_mul(self.period))
            .and_then(|d| self.epoch.checked_add(d))
            .unwrap_or(u64::MAX)
    }
}

/// What a payee publishes: the address to pay to, and when it stops being it.
///
/// A payer that uses a stale one puts the note in a stale scope, and nothing in
/// the protocol stops them --- which is why `valid_until` is published rather
/// than assumed, and why a payee that cares checks what came in against the
/// scope it expected.
pub struct Published {
    pub scope: String,
    pub address: Address,
    pub valid_until: u64,
}

impl ScopedWallet {
    /// The address to hand out at `now`.
    pub fn publish(&self, rolling: &Rolling, now: u64) -> Published {
        let scope = rolling.scope(now);
        Published {
            address: self.address(&scope),
            scope,
            valid_until: rolling.ends_at(now),
        }
    }

    /// Grant the period in force, expiring when the period does.
    ///
    /// The expiry and the roll line up on purpose: a grant that outlived its
    /// period would be current for a scope nothing is being paid into, which
    /// looks like access and is not, and a grant that ended early would look
    /// like revocation and would not be.
    pub fn grant_current(&self, rolling: &Rolling, grantee: &str, now: u64) -> ViewingGrant {
        let scope = rolling.scope(now);
        self.grant_until(&scope, grantee, now, rolling.ends_at(now))
    }
}

/// Whether this grant is for the period in force.
///
/// Separate from `check_grant`, which asks whether a grant is well formed and
/// current *by its own dates*. This asks the operational question: is it for
/// the scope money is going into now. A grant can pass one and fail the other,
/// and the two failures call for different things --- one is a bad grant and
/// the other is a wallet that has not rolled.
pub fn is_current_scope(grant: &ViewingGrant, rolling: &Rolling, now: u64) -> bool {
    grant.scope == rolling.scope(now)
}

/// What a payee should check about what arrived: that it came into the scope
/// it published, and not an older one it has since granted away.
pub fn arrived_off_schedule(
    ledger: &NoteLedger,
    owner: &ScopedWallet,
    rolling: &Rolling,
    now: u64,
    asset_key: &Pedersen,
) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let current = rolling.period_of(now);
    for period in 0..current {
        let scope = format!("{}:{}", rolling.name, period);
        let wallet = owner.wallet(&scope);
        for (_, opening) in ledger.scan(&wallet, asset_key) {
            out.push((opening.value, scope.clone()));
        }
    }
    out
}
