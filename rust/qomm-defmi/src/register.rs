//! Reading what an authoritative register actually sends, and reconciling with it.
//!
//! `reconcile.rs` is the arithmetic and it was all there was: a caller had to
//! produce the register's figure from somewhere, and nothing said where. In
//! practice a register does not expose a query --- it sends a file, once a day,
//! and somebody loads it. So the file is the interface.
//!
//! # The format
//!
//! One line a position, comma separated, with a header line naming the account
//! and the date. Deliberately the dullest thing that could work, because a
//! register's operations team is who writes the other end of it:
//!
//! ```text
//! # register, account, asset, as-of
//! JASDEC,customer-omnibus-001,JP3633400001,2026-08-22
//! p0,1200
//! p1,4500
//! p2,0
//! ```
//!
//! A line with no quantity is a refusal to parse, not a zero. A register that
//! means zero says zero --- and a file that ran out halfway would otherwise
//! reconcile to a smaller total and look like a break in the ledger rather than
//! a truncated download.
//!
//! # Two kinds of register, and the difference decides everything
//!
//! One that sends **a total** can be reconciled against and a break stays
//! pass-or-fail. One that sends **a figure per position** localises a break for
//! free and discloses nothing, because whoever holds the file already holds the
//! numbers. `Register::positions` returning `None` is the first kind, and it is
//! not a deficiency in this code --- it is what the counterparty sends.
//!
//! And the difference is larger than "where": **a total is blind to
//! reordering.** Two ledgers that disagree about which holder has which balance
//! and agree on the sum reconcile clean against a total, and a register sending
//! positions catches it. So when positions are sent they are always checked,
//! which costs one multiscalar since that check was batched --- there is no
//! reason to earn the blindness back.
//!
//! # What this does not do
//!
//! Connect to anything. There is no JASDEC client here and there should not be
//! one until somebody has credentials and a test environment; what there is, is
//! the shape the file arrives in and everything downstream of it, so that the
//! remaining work is a transport and not a design.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use qomm_zk::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};

use crate::reconcile::{
    check, check_positions, locate_break, prove, Attestation, BreakSearch, Reconciliation,
};

/// What one register said, on one day, about one account.
#[derive(Clone, Debug)]
pub struct Statement {
    pub register: String,
    pub account: String,
    pub asset: String,
    pub as_of: String,
    /// In the order the file gave them, which is the order the ledger's
    /// commitments have to be in. A register that reorders its file between
    /// days is a register whose file has to be sorted before use, and this
    /// keeps the order rather than sorting it silently.
    pub positions: Vec<(String, u64)>,
}

impl Statement {
    /// The sum of the positions, or `None` if they do not fit.
    ///
    /// It used to be a plain `sum`, which panics in debug and wraps in release.
    /// A total that wraps is a total that disagrees with its own positions and
    /// says nothing about it --- and this total goes into an attestation, so a
    /// wrapped one is signed and reconciled against.
    pub fn checked_total(&self) -> Option<u64> {
        self.positions
            .iter()
            .try_fold(0u64, |acc, (_, q)| acc.checked_add(*q))
    }

    /// The sum, saturating. For display and for callers that have already
    /// established the positions fit; `checked_total` is what an attestation
    /// should be built from.
    pub fn total(&self) -> u64 {
        self.checked_total().unwrap_or(u64::MAX)
    }

    pub fn attestation(&self, signature: Option<Signature>) -> Attestation {
        Attestation {
            register: self.register.clone(),
            account: self.account.clone(),
            asset: self.asset.clone(),
            total: self.total(),
            as_of: self.as_of.clone(),
            signature,
        }
    }

    pub fn signed_by(&self, key: &SigningKey) -> Attestation {
        let bare = self.attestation(None);
        let signature = key.sign(&bare.body());
        self.attestation(Some(signature))
    }

    pub fn quantities(&self) -> Vec<u64> {
        self.positions.iter().map(|(_, q)| *q).collect()
    }

    pub fn handles(&self) -> Vec<&str> {
        self.positions.iter().map(|(h, _)| h.as_str()).collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileError {
    Empty,
    Header(String),
    Line {
        number: usize,
        why: String,
    },
    /// The file did not say how long it was, or said something the rows
    /// disagree with. Both are the same failure seen from two sides.
    End(String),
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::Empty => write!(
                f,
                "the file is empty, which is not a \
                                           statement of zero holdings"
            ),
            FileError::Header(why) => write!(f, "the header: {why}"),
            FileError::Line { number, why } => write!(f, "line {number}: {why}"),
            FileError::End(why) => write!(f, "the end line: {why}"),
        }
    }
}

/// Read a position file exactly, refusing anything it is not sure of.
///
/// The file is a header, then a row per position, then a line that says how
/// many rows there were and what they came to:
///
/// ```text
/// JASDEC,customer-omnibus-001,JP3633400001,2026-08-22
/// p0,1200
/// p1,4500
/// end,2,5700
/// ```
///
/// That last line is the whole reason the format is not just rows. A file that
/// lost rows off the end is a well-formed statement of a smaller holding, and
/// nothing in its content says otherwise --- reconciliation reports a break
/// against a ledger that is correct, and the morning goes to the wrong place.
/// A file has to declare its own length for truncation to be visible, and the
/// declaration has to be at the end, where truncation takes it.
///
/// It does not defend against an edited file: anyone who drops a row can drop
/// it from the count too. That is what the register's signature is for. This
/// catches the accident, which is the common one.
pub fn parse(text: &str) -> Result<Statement, FileError> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate();
    let (_, header) = lines.next().ok_or(FileError::Empty)?;
    let fields: Vec<&str> = header.split(',').map(str::trim).collect();
    if fields.len() != 4 {
        return Err(FileError::Header(format!(
            "wanted register, account, asset and a date; got {} field(s)",
            fields.len()
        )));
    }
    let mut positions = Vec::new();
    let mut declared: Option<(usize, u64)> = None;
    for (index, line) in lines.by_ref() {
        let mut parts = line.split(',').map(str::trim);
        let handle = parts.next().unwrap_or_default();
        if handle == "end" {
            let count = parts
                .next()
                .ok_or_else(|| FileError::End("wanted a row count and a total".into()))?;
            let total = parts
                .next()
                .ok_or_else(|| FileError::End("wanted a total after the row count".into()))?;
            if parts.next().is_some() {
                return Err(FileError::End("more than a count and a total".into()));
            }
            let count: usize = count
                .parse()
                .map_err(|_| FileError::End(format!("{count} is not a row count")))?;
            let total: u64 = total
                .parse()
                .map_err(|_| FileError::End(format!("{total} is not a total")))?;
            declared = Some((count, total));
            break;
        }
        // A missing quantity is a refusal and not a zero: a truncated download
        // would otherwise reconcile to a smaller total and look like a break in
        // the ledger rather than a broken file.
        let quantity = parts.next().ok_or(FileError::Line {
            number: index + 1,
            why: "no quantity. A register that means zero says zero.".into(),
        })?;
        let quantity: u64 = quantity.parse().map_err(|_| FileError::Line {
            number: index + 1,
            why: format!("{quantity} is not a quantity"),
        })?;
        if handle.is_empty() {
            return Err(FileError::Line {
                number: index + 1,
                why: "no handle".into(),
            });
        }
        if parts.next().is_some() {
            return Err(FileError::Line {
                number: index + 1,
                why: "more than a handle and a quantity".into(),
            });
        }
        positions.push((handle.to_string(), quantity));
    }
    if positions.is_empty() {
        return Err(FileError::Empty);
    }
    if lines.next().is_some() {
        return Err(FileError::End("there are rows after it".into()));
    }
    let (count, total) = declared.ok_or_else(|| {
        FileError::End(
            "the file does not say how many rows it has, so a file that lost \
         some of them would read as a smaller holding"
                .into(),
        )
    })?;
    let statement = Statement {
        register: fields[0].to_string(),
        account: fields[1].to_string(),
        asset: fields[2].to_string(),
        as_of: fields[3].to_string(),
        positions,
    };
    if statement.positions.len() != count {
        return Err(FileError::End(format!(
            "it declares {count} row(s) and the file has {}",
            statement.positions.len()
        )));
    }
    let found = statement
        .checked_total()
        .ok_or_else(|| FileError::End("the positions do not fit a total".into()))?;
    if found != total {
        return Err(FileError::End(format!(
            "it declares a total of {total} and the rows come to {found}"
        )));
    }
    Ok(statement)
}

/// Where a figure comes from. A file today; a connection when there is one.
pub trait Register {
    fn statement(&self) -> &Statement;

    /// A figure per position, when the register sends one.
    ///
    /// `None` is not a deficiency here --- it is what the counterparty sends,
    /// and it decides whether a break can be localised at all.
    fn positions(&self) -> Option<&[(String, u64)]> {
        Some(&self.statement().positions)
    }

    fn signature(&self) -> Option<&Signature> {
        None
    }
}

/// A register that sent a file.
pub struct FileRegister {
    pub statement: Statement,
    pub signature: Option<Signature>,
}

impl FileRegister {
    pub fn read(text: &str) -> Result<Self, FileError> {
        Ok(FileRegister {
            statement: parse(text)?,
            signature: None,
        })
    }
}

impl Register for FileRegister {
    fn statement(&self) -> &Statement {
        &self.statement
    }
    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
}

/// A register that sends only a total, which is the common case one level up.
pub struct TotalOnly {
    pub statement: Statement,
}

impl Register for TotalOnly {
    fn statement(&self) -> &Statement {
        &self.statement
    }
    fn positions(&self) -> Option<&[(String, u64)]> {
        None
    }
}

/// What a reconciliation run produced, in the shape an operations team acts on.
pub struct Report {
    pub register: String,
    pub account: String,
    pub asset: String,
    pub as_of: String,
    pub positions: usize,
    pub register_total: u64,
    pub agrees: bool,
    pub reason: String,
    /// Which positions disagree, when the register sends enough to say.
    pub broken: Vec<(String, u64)>,
    /// How the break was localised, and what that made public.
    pub search: Option<BreakSearch>,
    pub reconciliation: Option<Reconciliation>,
}

impl Report {
    pub fn text(&self) -> String {
        let mut out = format!(
            "{} / {} / {} as of {}\n{} position(s), the register says {}\n",
            self.register,
            self.account,
            self.asset,
            self.as_of,
            self.positions,
            self.register_total
        );
        if self.agrees {
            out.push_str(
                "\nAgrees. No balance was opened and nothing left that \
                          both sides did not already hold.\n",
            );
            return out;
        }
        out.push_str(&format!("\nDoes not agree: {}\n", self.reason));
        if self.broken.is_empty() && self.search.is_none() {
            out.push_str(
                "\nThe register sends a total and not a figure per \
                          position, so there is nothing here that can say where. \
                          Localising it needs the register to answer for \
                          sub-ranges, and every sub-range it answers becomes \
                          public.\n",
            );
            return out;
        }
        for (handle, expected) in &self.broken {
            out.push_str(&format!(
                "  {handle}: the register says {expected} and \
                                   the ledger holds something else\n"
            ));
        }
        if let Some(search) = &self.search {
            out.push_str(&format!(
                "\nLocalised with {} sub-range proof(s); {} sub-total(s) are now \
                 public, the narrowest covering {} position(s) --- which at one \
                 position is a balance.\n",
                search.proofs,
                search.ranges_made_public.len(),
                search.narrowest()
            ));
        }
        out
    }
}

/// Reconcile a ledger against what a register sent, and say what to do about it.
///
/// The order of `commitments` is the order of the register's file. Sorting one
/// side silently is how a reconciliation reports a break that is really a
/// disagreement about ordering, so neither side is sorted here.
pub fn run<R: RngCore + CryptoRng>(
    key: &Pedersen,
    register: &dyn Register,
    commitments: &[RistrettoPoint],
    blindings: &[Scalar],
    registrar: Option<&VerifyingKey>,
    rng: &mut R,
) -> Report {
    let statement = register.statement();
    let attestation = statement.attestation(register.signature().cloned());
    let mut report = Report {
        register: statement.register.clone(),
        account: statement.account.clone(),
        asset: statement.asset.clone(),
        as_of: statement.as_of.clone(),
        positions: statement.positions.len(),
        register_total: statement.total(),
        agrees: false,
        reason: String::new(),
        broken: Vec::new(),
        search: None,
        reconciliation: None,
    };
    if commitments.len() != statement.positions.len() {
        report.reason = format!(
            "the register lists {} position(s) and the ledger offered {}",
            statement.positions.len(),
            commitments.len()
        );
        return report;
    }
    let reconciliation = match prove(key, commitments, blindings, &attestation, rng) {
        Ok(r) => r,
        Err(why) => {
            report.reason = why.to_string();
            return report;
        }
    };
    let totals_agree = check(key, commitments, &reconciliation, registrar);

    // The per-position check runs whether or not the totals agreed, and that is
    // not belt and braces. **A total is blind to reordering**: a register and a
    // ledger that disagree about which holder has which balance, and agree on
    // the sum, reconcile clean. It costs one multiscalar since the check was
    // batched, so there is no reason to earn that blindness back.
    let positions = register.positions();
    let broken = positions.map(|p| {
        let expected: Vec<u64> = p.iter().map(|(_, q)| *q).collect();
        check_positions(key, commitments, blindings, &expected, rng)
    });

    match (&totals_agree, broken.as_deref()) {
        (Ok(()), None) | (Ok(()), Some([])) => {
            report.agrees = true;
            report.reconciliation = Some(reconciliation);
            return report;
        }
        (Ok(()), Some(_)) => {
            report.reason = "the totals agree and the positions do not, which is \
                             a reordering or an offsetting pair --- a sum cannot \
                             see either"
                .into();
        }
        (Err(why), _) => report.reason = why.clone(),
    }

    let (Some(positions), Some(broken)) = (positions, broken) else {
        return report;
    };
    report.broken = broken
        .iter()
        .map(|i| (positions[*i].0.clone(), positions[*i].1))
        .collect();
    if report.broken.is_empty() {
        // Every position holds what it should and the total still disagrees,
        // which means the register's own arithmetic is what differs.
        report.reason = format!(
            "{}, and yet every position holds what the register says --- so the \
             disagreement is in the register's own total",
            report.reason
        );
    }
    report
}

/// The same, for a register that answers about sub-ranges rather than positions.
///
/// Kept separate because it is the expensive and disclosing path, and having to
/// ask for it by name is the point.
pub fn localise<R: RngCore + CryptoRng>(
    key: &Pedersen,
    commitments: &[RistrettoPoint],
    blindings: &[Scalar],
    subtotals: &BTreeMap<(usize, usize), u64>,
    expected: u64,
    rng: &mut R,
) -> Result<BreakSearch, String> {
    locate_break(
        key,
        commitments,
        blindings,
        |low, high| subtotals.get(&(low, high)).copied(),
        expected,
        rng,
    )
}
