//! DeCCP: the clearing house as a slot, and novation as arithmetic.
//!
//! `netting.rs` measured what this is for. Netting the rails saved only 1.73x,
//! because most of every order is the payment instruction and an instruction
//! does not net. Replacing per-trade instructions with one attestation over the
//! cycle removed that and gave 17.95x --- and the cost was that the layer stops
//! checking individual trades, so the split between participants is attested
//! rather than verified.
//!
//! **Under novation there is no split left to verify.** A trade between A and B
//! becomes A against the house and the house against B, and the original
//! obligation stops existing. That is not bookkeeping; it is the legal effect
//! the institution is for, and verifying an allocation that has been
//! extinguished is not a check anybody was owed.
//!
//! **And novation is free.** An obligation is a commitment, so replacing one
//! edge with two is two point additions and no proof: nothing is asserted, the
//! graph is rewritten. The house's book is flat by the same construction --- it
//! owes exactly what it is owed, per asset --- so that is one comparison rather
//! than a statement anybody has to establish.
//!
//! # Two things the first version left open, closed here
//!
//! **A house cannot invent a trade.** Both parties sign their own obligation
//! before it is novated, so an edge that nobody agreed to cannot be produced ---
//! the house would have to forge a signature. What remains is that a house can
//! *omit* a real trade, and that is a different shape of failure: the two
//! parties hold the signed obligation, so an omission is something they can
//! show, where an invention would have been something nobody could see.
//!
//! **A member cleared at two houses has two positions, not one.** Default is
//! resolved per provider and the resolution refuses to offset: a shortfall at
//! one house is absorbed by that house's waterfall alone, and the total loss is
//! the sum across houses rather than the net. Netting across providers is
//! cross-margining, which is an agreement between clearing houses and not an
//! arithmetic identity; summing the positions quietly would be inventing it.
//!
//! # What is still trusted
//!
//! That the house did not drop a trade, and that novation on a ledger which is
//! a mirror of a register has legal effect. The first is visible to the parties
//! and the second is that register's rulebook. Neither is arithmetic.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use qomm_zk::pedersen::encode;
use sha2::{Digest, Sha256};

use crate::credit::{CreditCtx, CreditLine, Tranche, Waterfall};

pub const CCP_DOMAIN: &[u8] = b"QOMM:DEFMI:CCP:v1";

/// One side owing another, with the amount committed and nothing else.
#[derive(Clone)]
pub struct Obligation {
    pub payer: Vec<u8>,
    pub payee: Vec<u8>,
    pub asset: String,
    pub commitment: RistrettoPoint,
}

impl Obligation {
    /// What both parties sign. Naming the asset and both sides means a
    /// signature cannot be moved to another instrument or another counterparty.
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.asset.len());
        out.extend_from_slice(CCP_DOMAIN);
        out.extend_from_slice(b":obligation:");
        for part in [
            self.payer.as_slice(),
            self.payee.as_slice(),
            self.asset.as_bytes(),
        ] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out.extend_from_slice(encode(&self.commitment).as_bytes());
        out
    }
}

/// An obligation both sides agreed to.
///
/// The pair of signatures is what stops a house inventing an edge. It is not
/// what stops it dropping one --- nothing here is, and the parties holding this
/// object are what make an omission arguable.
#[derive(Clone)]
pub struct SignedObligation {
    pub obligation: Obligation,
    pub by_payer: Signature,
    pub by_payee: Signature,
}

/// A graph of obligations rewritten so every edge touches the house.
///
/// Both graphs are kept because the whole claim is that the second is the first
/// with one party interposed, and a reader who cannot see both has to take that
/// on trust.
pub struct Novation {
    pub house: Vec<u8>,
    pub asset: String,
    pub before: Vec<SignedObligation>,
    pub after: Vec<Obligation>,
    pub owed_to_house: RistrettoPoint,
    pub owed_by_house: RistrettoPoint,
}

impl Novation {
    pub fn edges(&self) -> usize {
        self.before.len()
    }
}

/// One clearing house: it novates, it attests, and it is in the waterfall.
pub struct ClearingProvider {
    pub name: String,
    pub handle: Vec<u8>,
    signing: SigningKey,
}

impl ClearingProvider {
    pub fn new(name: &str, handle: &[u8], signing: SigningKey) -> Self {
        ClearingProvider {
            name: name.to_string(),
            handle: handle.to_vec(),
            signing,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Interpose this house between every pair. Two point additions an edge.
    ///
    /// No proof is produced because none is needed: the operation rewrites the
    /// graph and leaves the product over it where it was. What a verifier does
    /// afterwards is [`check_novation`], which redoes the same arithmetic.
    pub fn novate(&self, edges: &[SignedObligation]) -> Result<Novation, &'static str> {
        let first = edges.first().ok_or("nothing to novate")?;
        let asset = first.obligation.asset.clone();
        if edges.iter().any(|e| e.obligation.asset != asset) {
            // Commitments under different tags do not combine, so a mixed graph
            // has to fail here rather than net one instrument out as another.
            return Err("an obligation graph is per asset");
        }
        let mut after = Vec::with_capacity(edges.len() * 2);
        let mut to_house = RistrettoPoint::identity();
        let mut by_house = RistrettoPoint::identity();
        for edge in edges {
            let o = &edge.obligation;
            after.push(Obligation {
                payer: o.payer.clone(),
                payee: self.handle.clone(),
                asset: asset.clone(),
                commitment: o.commitment,
            });
            after.push(Obligation {
                payer: self.handle.clone(),
                payee: o.payee.clone(),
                asset: asset.clone(),
                commitment: o.commitment,
            });
            to_house += o.commitment;
            by_house += o.commitment;
        }
        Ok(Novation {
            house: self.handle.clone(),
            asset,
            before: edges.to_vec(),
            after,
            owed_to_house: to_house,
            owed_by_house: by_house,
        })
    }

    /// That these were the trades --- the one claim that is not arithmetic.
    pub fn attest(&self, novation: &Novation, cycle: &[u8]) -> Attestation {
        let digest = attestation_digest(novation, cycle);
        Attestation {
            provider: self.name.clone(),
            handle: self.handle.clone(),
            cycle: cycle.to_vec(),
            digest,
            signature: self.signing.sign(&digest),
            edges: novation.edges(),
            asset: novation.asset.clone(),
        }
    }
}

pub struct Attestation {
    pub provider: String,
    pub handle: Vec<u8>,
    pub cycle: Vec<u8>,
    pub digest: [u8; 32],
    pub signature: Signature,
    pub edges: usize,
    pub asset: String,
}

pub fn attestation_digest(novation: &Novation, cycle: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CCP_DOMAIN);
    hasher.update(b":novation:");
    // Length-prefixed, because these are variable length and concatenating
    // them is ambiguous: cycle `a` with house `bc` hashes the same bytes as
    // cycle `ab` with house `c`, so one provider's attestation moves to
    // another provider and another cycle under the same signature.
    for field in [cycle, &novation.house[..], novation.asset.as_bytes()] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    for edge in &novation.before {
        hasher.update(edge.obligation.body());
    }
    hasher.finalize().into()
}

/// Sign one obligation as one of its two parties.
pub fn sign_obligation(
    obligation: &Obligation,
    payer: &SigningKey,
    payee: &SigningKey,
) -> SignedObligation {
    let body = obligation.body();
    SignedObligation {
        obligation: obligation.clone(),
        by_payer: payer.sign(&body),
        by_payee: payee.sign(&body),
    }
}

/// Whether both parties agreed to this edge.
///
/// Run before novation is believed, not after: an edge nobody agreed to should
/// never reach a book.
pub fn check_agreement(
    edge: &SignedObligation,
    payer: &VerifyingKey,
    payee: &VerifyingKey,
) -> Result<(), &'static str> {
    let body = edge.obligation.body();
    payer
        .verify(&body, &edge.by_payer)
        .map_err(|_| "the payer did not sign this")?;
    payee
        .verify(&body, &edge.by_payee)
        .map_err(|_| "the payee did not sign this")?;
    Ok(())
}

/// That the second graph is the first with one party interposed.
///
/// Every edge is replaced by exactly two carrying the same commitment, and the
/// house's book is flat. None of it needs a proof: it is the same arithmetic
/// done again by somebody with no secrets.
pub fn check_novation(house: &[u8], novation: &Novation) -> Result<(), String> {
    if novation.house != house {
        return Err("novated by a different house than the one being checked".into());
    }
    if novation.after.len() != 2 * novation.before.len() {
        return Err(format!(
            "{} edges became {}, not {}",
            novation.before.len(),
            novation.after.len(),
            2 * novation.before.len()
        ));
    }
    let mut to_house = RistrettoPoint::identity();
    let mut by_house = RistrettoPoint::identity();
    for (index, edge) in novation.before.iter().enumerate() {
        let o = &edge.obligation;
        let first = &novation.after[2 * index];
        let second = &novation.after[2 * index + 1];
        if first.payer != o.payer || first.payee != house {
            return Err(format!(
                "edge {index} does not run from its payer to the house"
            ));
        }
        if second.payer != house || second.payee != o.payee {
            return Err(format!(
                "edge {index} does not run from the house to its payee"
            ));
        }
        // Compared as points rather than as compressed encodings. Ristretto
        // equality is a cross-multiplication; compressing is a field inversion,
        // and doing four of them an edge was most of this check --- 13 us
        // against the 0.9 us the novation itself takes. Same answer, and
        // Ristretto's whole point is that equal points have equal encodings.
        if first.commitment != o.commitment || second.commitment != o.commitment {
            return Err(format!("edge {index} changed amount on the way through"));
        }
        if o.asset != novation.asset
            || first.asset != novation.asset
            || second.asset != novation.asset
        {
            return Err(format!("edge {index} is in another asset"));
        }
        to_house += first.commitment;
        by_house += second.commitment;
    }
    if to_house != novation.owed_to_house || by_house != novation.owed_by_house {
        return Err("the published totals are not the totals of the edges".into());
    }
    if to_house != by_house {
        return Err(
            "the house's book is not flat: it owes something other than \
                    what it is owed"
                .into(),
        );
    }
    Ok(())
}

pub fn check_attestation(
    attestation: &Attestation,
    novation: &Novation,
    provider: &VerifyingKey,
) -> Result<(), &'static str> {
    if attestation.digest != attestation_digest(novation, &attestation.cycle) {
        return Err("the attestation is over a different trade set");
    }
    provider
        .verify(&attestation.digest, &attestation.signature)
        .map_err(|_| "not signed by that provider")
}

/// Each participant's obligation to the house and claim on it.
///
/// Two additions a participant and no proof anywhere: a net position under
/// novation is not derived, it is accumulated.
pub fn net_positions(novation: &Novation) -> BTreeMap<Vec<u8>, (RistrettoPoint, RistrettoPoint)> {
    let mut out: BTreeMap<Vec<u8>, (RistrettoPoint, RistrettoPoint)> = BTreeMap::new();
    for edge in &novation.after {
        if edge.payer == novation.house {
            let slot = out
                .entry(edge.payee.clone())
                .or_insert((RistrettoPoint::identity(), RistrettoPoint::identity()));
            slot.1 += edge.commitment;
        } else {
            let slot = out
                .entry(edge.payer.clone())
                .or_insert((RistrettoPoint::identity(), RistrettoPoint::identity()));
            slot.0 += edge.commitment;
        }
    }
    out
}

// --- the waterfall the provider is in ---------------------------------------

/// The default order, with one provider's own capital inside it.
///
/// Four layers is the standard arrangement and the order *is* the arrangement:
/// the defaulter's margin, the defaulter's contribution to the fund, **the
/// clearing provider's own capital**, then everybody else's contributions. The
/// third layer is why a provider's attestation is worth relying on --- it is the
/// layer that makes attesting expensive to get wrong.
pub struct ProviderWaterfall {
    pub provider: String,
    pub tranches: Vec<Tranche>,
    /// Which tranche is the provider's own capital, by position.
    ///
    /// It used to be found by looking for the words "provider capital" in a
    /// tranche's name. A name is not a commitment --- anybody assembling a
    /// waterfall can write those words on any layer, or on a layer committing
    /// zero --- and this is the layer that makes an attestation expensive to
    /// get wrong, so what identifies it cannot be a label.
    pub own: usize,
}

/// The four layers in the order CPMI-IOSCO puts them.
pub fn for_provider(
    provider: &str,
    defaulter_margin: RistrettoPoint,
    defaulter_fund: RistrettoPoint,
    provider_capital: RistrettoPoint,
    mutualised: RistrettoPoint,
) -> ProviderWaterfall {
    ProviderWaterfall {
        provider: provider.to_string(),
        tranches: vec![
            Tranche {
                name: format!("{provider}:defaulter margin"),
                commitment: defaulter_margin,
            },
            Tranche {
                name: format!("{provider}:defaulter fund contribution"),
                commitment: defaulter_fund,
            },
            Tranche {
                name: format!("{provider}:provider capital"),
                commitment: provider_capital,
            },
            Tranche {
                name: format!("{provider}:mutualised pool"),
                commitment: mutualised,
            },
        ],
        own: 2,
    }
}

impl ProviderWaterfall {
    /// The provider's own layer, if `own` points at one.
    pub fn own_capital(&self) -> Option<&Tranche> {
        self.tranches.get(self.own)
    }

    pub fn has_own_capital(&self) -> bool {
        self.own_capital().is_some()
    }

    pub fn waterfall(&self, key: qomm_zk::pedersen::Pedersen, bits: usize) -> Waterfall {
        Waterfall::new(key, self.tranches.clone(), bits)
    }
}

struct Admitted {
    handle: Vec<u8>,
    identity: VerifyingKey,
    margin: CreditLine,
    waterfall: ProviderWaterfall,
}

/// Which providers a deployment accepts, and on what terms.
///
/// A slot rather than a dependency: nothing in `netting.rs` or `settlement.rs`
/// knows which house cleared a trade, and a deployment with no provider at all
/// is the bilateral case, which still works and pays per-trade proofs for it.
#[derive(Default)]
pub struct ClearingRegistry {
    providers: BTreeMap<String, Admitted>,
}

impl ClearingRegistry {
    pub fn new() -> Self {
        ClearingRegistry::default()
    }

    /// A provider is admitted only with margin posted and a tranche of its own.
    ///
    /// The second condition is not bookkeeping. An attestation from a party
    /// with nothing in the waterfall costs it nothing to get wrong, and an
    /// attestation that costs nothing to get wrong is not an attestation.
    /// `ctx` is the credit context the margin was granted under. Required
    /// because the margin used to be stored without being verified at all: a
    /// line built by anybody, over anybody's collateral, proving nothing, and
    /// the registry then reported the provider as margined.
    pub fn admit(
        &mut self,
        ctx: &CreditCtx,
        provider: &ClearingProvider,
        margin: CreditLine,
        waterfall: ProviderWaterfall,
    ) -> Result<(), String> {
        if !waterfall.has_own_capital() {
            return Err(format!(
                "{}: no tranche of its own, so its attestation \
                                costs it nothing to get wrong",
                provider.name
            ));
        }
        if waterfall.provider != provider.name {
            return Err(format!(
                "{}: a waterfall built for {}",
                provider.name, waterfall.provider
            ));
        }
        if margin.handle != provider.handle {
            return Err(format!(
                "{}: the margin is under another handle, so it \
                                is not this provider that is margined",
                provider.name
            ));
        }
        ctx.check(&margin)
            .map_err(|why| format!("{}: the margin's backing proof: {why}", provider.name))?;
        self.providers.insert(
            provider.name.clone(),
            Admitted {
                handle: provider.handle.clone(),
                identity: provider.verifying_key(),
                margin,
                waterfall,
            },
        );
        Ok(())
    }

    pub fn names(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Everything a third party can establish about one cleared cycle.
    ///
    /// `parties` supplies each participant's verifying key. Without it the
    /// agreement check cannot run, and the check is the thing that stops a
    /// house inventing an edge, so it is required rather than optional.
    pub fn check_cycle(
        &self,
        attestation: &Attestation,
        novation: &Novation,
        parties: &BTreeMap<Vec<u8>, VerifyingKey>,
    ) -> Result<(), String> {
        let entry = self
            .providers
            .get(&attestation.provider)
            .ok_or_else(|| format!("{} is not an admitted provider", attestation.provider))?;
        if entry.handle != novation.house {
            return Err("novated under a handle this provider did not register".into());
        }
        check_novation(&entry.handle, novation)?;
        for (index, edge) in novation.before.iter().enumerate() {
            let payer = parties
                .get(&edge.obligation.payer)
                .ok_or_else(|| format!("edge {index}: the payer is not a known party"))?;
            let payee = parties
                .get(&edge.obligation.payee)
                .ok_or_else(|| format!("edge {index}: the payee is not a known party"))?;
            check_agreement(edge, payer, payee).map_err(|why| format!("edge {index}: {why}"))?;
        }
        check_attestation(attestation, novation, &entry.identity).map_err(|why| why.to_string())
    }

    pub fn waterfall_for(&self, provider: &str) -> Option<&ProviderWaterfall> {
        self.providers.get(provider).map(|a| &a.waterfall)
    }

    /// The verified margin line admitted for a provider. Exposing the checked
    /// value makes collateral monitoring possible without accepting a second,
    /// unverified copy from an operator.
    pub fn margin_for(&self, provider: &str) -> Option<&CreditLine> {
        self.providers.get(provider).map(|a| &a.margin)
    }
}

/// A member's default, resolved at every house it cleared at, without offsetting.
///
/// The refusal is the content. A shortfall at one house is absorbed by that
/// house's waterfall alone; the total loss is the **sum** across houses and not
/// the net. Netting across providers is cross-margining, which is an agreement
/// between clearing houses rather than an arithmetic identity, and a design
/// that quietly summed the positions would be inventing it.
pub struct DefaultAcrossProviders {
    pub member: Vec<u8>,
    pub per_provider: Vec<(String, u64)>,
}

impl DefaultAcrossProviders {
    /// What the member owes in total, which is the sum and never the net.
    /// The sum across providers, or `None` if it does not fit.
    ///
    /// A wrapped shortfall understates itself, and this number decides how much
    /// capital is called. The plain `sum` it replaces panicked in debug and
    /// wrapped in release.
    pub fn checked_total_shortfall(&self) -> Option<u64> {
        self.per_provider
            .iter()
            .try_fold(0u64, |acc, (_, amount)| acc.checked_add(*amount))
    }

    pub fn total_shortfall(&self) -> u64 {
        self.checked_total_shortfall().unwrap_or(u64::MAX)
    }

    /// Stated so a caller cannot mistake the absence of offsetting for an
    /// oversight: there is no netted figure, and asking for one is the question
    /// this design declines to answer.
    pub fn netted_shortfall(&self) -> Option<u64> {
        None
    }

    pub fn houses(&self) -> usize {
        self.per_provider.len()
    }
}

/// The compressed form, for a caller that wants to publish the flat book.
pub fn flat_book(novation: &Novation) -> (CompressedRistretto, CompressedRistretto) {
    (
        encode(&novation.owed_to_house),
        encode(&novation.owed_by_house),
    )
}
