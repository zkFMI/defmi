//! Read the shares that MP-SPDZ writes with `sint.write_to_file`.
//!
//! A file starts with an eight-byte little-endian header length. Inside that
//! header are the ten-byte type name, one sign byte, a little-endian `u32`
//! containing the prime's minimal byte length, the big-endian prime, and a
//! little-endian `u32` Montgomery flag. Body elements are little-endian and
//! occupy a whole number of 64-bit GMP limbs.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const NAME_BYTES: usize = 10;
const SIGN_OFFSET: usize = 10;
const LENGTH_OFFSET: usize = 11;
const PRIME_OFFSET: usize = 15;
const LIMB_BYTES: usize = 8;

pub const HEADER_NAMES: [&str; 2] = ["winner_key", "qty"];

/// The exact order emitted by `program::build_program(persist_wires = true)`.
pub const WIRE_NAMES: [&str; 23] = [
    "ask_level",
    "spread",
    "slope",
    "invcoef",
    "inv",
    "maxqty",
    "expiry",
    "active",
    "depth",
    "skew",
    "ask",
    "bid",
    "fits",
    "ok",
    "key",
    "fits_margin",
    "fresh_margin",
    "fresh_bit",
    "fits_product",
    "fresh_product",
    "both",
    "gated",
    "cost",
];

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// An arbitrary-width non-negative field element, least-significant limb first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldElement {
    limbs: Vec<u64>,
}

impl FieldElement {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self { limbs: vec![value] }
        }
    }

    pub fn from_u128(value: u128) -> Self {
        let mut limbs = vec![value as u64, (value >> 64) as u64];
        normalize(&mut limbs);
        Self { limbs }
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(LIMB_BYTES));
        for chunk in bytes.chunks(LIMB_BYTES) {
            let mut limb = [0_u8; LIMB_BYTES];
            limb[..chunk.len()].copy_from_slice(chunk);
            limbs.push(u64::from_le_bytes(limb));
        }
        normalize(&mut limbs);
        Self { limbs }
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut little = bytes.to_vec();
        little.reverse();
        Self::from_bytes_le(&little)
    }

    pub fn to_bytes_le(&self, width: usize) -> Result<Vec<u8>, Error> {
        let required = self.limbs.len().saturating_mul(LIMB_BYTES);
        if required > width {
            return Err(Error::Invalid(format!(
                "field element needs {required} bytes but width is {width}"
            )));
        }
        let mut bytes = Vec::with_capacity(width);
        for limb in &self.limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        bytes.resize(width, 0);
        Ok(bytes)
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        if self.limbs.is_empty() {
            return vec![0];
        }
        let mut bytes = self
            .to_bytes_le(self.limbs.len() * LIMB_BYTES)
            .expect("the element's own width");
        while bytes.last() == Some(&0) && bytes.len() > 1 {
            bytes.pop();
        }
        bytes.reverse();
        bytes
    }

    pub fn bit_length(&self) -> usize {
        self.limbs.last().map_or(0, |last| {
            (self.limbs.len() - 1) * 64 + (64 - last.leading_zeros() as usize)
        })
    }

    pub fn as_u128(&self) -> Option<u128> {
        match self.limbs.as_slice() {
            [] => Some(0),
            [low] => Some(*low as u128),
            [low, high] => Some(*low as u128 | ((*high as u128) << 64)),
            _ => None,
        }
    }

    fn padded_limbs(&self, width: usize) -> Vec<u64> {
        let mut limbs = self.limbs.clone();
        limbs.resize(width, 0);
        limbs
    }
}

impl Ord for FieldElement {
    fn cmp(&self, other: &Self) -> Ordering {
        self.limbs
            .len()
            .cmp(&other.limbs.len())
            .then_with(|| self.limbs.iter().rev().cmp(other.limbs.iter().rev()))
    }
}

impl PartialOrd for FieldElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.limbs.is_empty() {
            return f.write_str("0");
        }
        let mut limbs = self.limbs.clone();
        let mut digits = Vec::new();
        while !limbs.is_empty() {
            let mut remainder = 0_u128;
            for limb in limbs.iter_mut().rev() {
                let value = (remainder << 64) | *limb as u128;
                *limb = (value / 10) as u64;
                remainder = value % 10;
            }
            digits.push(b'0' + remainder as u8);
            normalize(&mut limbs);
        }
        digits.reverse();
        f.write_str(std::str::from_utf8(&digits).expect("decimal digits"))
    }
}

fn normalize(limbs: &mut Vec<u64>) {
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub name: [u8; NAME_BYTES],
    pub negative: bool,
    pub prime: FieldElement,
    pub montgomery: bool,
    pub element_bytes: usize,
    pub header_bytes: usize,
    pub data_offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Persisted {
    pub party: usize,
    pub path: PathBuf,
    pub prime: FieldElement,
    pub element_bytes: usize,
    pub shares: Vec<FieldElement>,
    pub montgomery: bool,
}

/// Every share map uses MP-SPDZ's one-based Shamir evaluation point as its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wires {
    pub prime: FieldElement,
    pub winner_key: BTreeMap<usize, FieldElement>,
    pub qty: BTreeMap<usize, FieldElement>,
    pub makers: Vec<BTreeMap<&'static str, BTreeMap<usize, FieldElement>>>,
    pub runs_in_file: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRangeHandoff {
    pub value_share: FieldElement,
    pub blinding_share: FieldElement,
    /// `(bit share, bit-blinding share, r_bit * (1 - bit) share)` in
    /// little-endian bit order.
    pub bits: Vec<(FieldElement, FieldElement, FieldElement)>,
}

/// The proof material one MPC node reads from its own Persistence file.
/// There is deliberately no API here that returns every party's private
/// handoff in one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalZkpiHandoff {
    pub party: usize,
    pub path: PathBuf,
    pub prime: FieldElement,
    pub winner_key_share: FieldElement,
    /// Shamir evaluation of the winning Maker's venue-handle scalar.  Proof
    /// nodes expose only group evaluations and never reconstruct this scalar.
    pub maker_handle_share: FieldElement,
    pub amount: LocalRangeHandoff,
    pub price: LocalRangeHandoff,
    /// Non-negative distance between the selected quote and the Taker's
    /// pre-signed limit, with direction already applied inside MPC.
    pub price_limit_difference: LocalRangeHandoff,
    pub runs_in_file: usize,
}

/// One node's DvP witness handoff.  The factor is the same MPC-computed price
/// share used by zkPI; `product_cross_share` binds quantity times price to the
/// cash commitment.  Both remainder ranges contain only this party's shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalDvpHandoff {
    pub party: usize,
    pub path: PathBuf,
    pub prime: FieldElement,
    pub price_share: FieldElement,
    pub price_blinding_share: FieldElement,
    /// Shamir evaluation of the exact cash amount `quantity * price`.
    pub cash_value_share: FieldElement,
    /// Shamir evaluation of the blinding of the cash amount commitment.
    pub cash_blinding_share: FieldElement,
    pub product_cross_share: FieldElement,
    pub securities_remainder: LocalRangeHandoff,
    pub cash_remainder: LocalRangeHandoff,
    /// Selected Maker policy pool after subtracting the exact delivery leg.
    /// This range is distinct from both DvP payer refunds.
    pub maker_pool_remainder: LocalRangeHandoff,
    pub runs_in_file: usize,
}

pub const QUOTE_POLICY_BLINDING_NAMES: [&str; 9] = [
    "ask_level",
    "spread",
    "slope",
    "invcoef",
    "inv",
    "maxqty",
    "expiry",
    "active",
    "use_ref",
];

pub const QUOTE_DERIVED_BLINDING_NAMES: [&str; 10] = [
    "depth",
    "skew",
    "fits_bit",
    "fits_product",
    "fresh_bit",
    "fresh_product",
    "both",
    "ok",
    "gated",
    "cost",
];

pub const QUOTE_CROSS_NAMES: [&str; 11] = [
    "depth",
    "skew",
    "fits_bit",
    "fits_product",
    "fresh_bit",
    "fresh_product",
    "active",
    "reference",
    "both",
    "ok",
    "gated",
];

/// One Maker's complete local quote-proof witness. Every scalar is one
/// party's Shamir evaluation; this type never contains a party-indexed map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalQuoteMakerHandoff {
    pub core_wire_shares: BTreeMap<&'static str, FieldElement>,
    pub use_ref_share: FieldElement,
    pub policy_blinding_shares: BTreeMap<&'static str, FieldElement>,
    pub derived_blinding_shares: BTreeMap<&'static str, FieldElement>,
    pub cross_shares: BTreeMap<&'static str, FieldElement>,
    pub fits_witness: LocalRangeHandoff,
    pub fresh_witness: LocalRangeHandoff,
    pub key_blinding_share: FieldElement,
    pub minimality: LocalRangeHandoff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalQuoteProofHandoff {
    pub party: usize,
    pub path: PathBuf,
    pub prime: FieldElement,
    pub qty_share: FieldElement,
    pub qty_blinding_share: FieldElement,
    pub makers: Vec<LocalQuoteMakerHandoff>,
    pub runs_in_file: usize,
}

fn zkpi_values_per_run(
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
) -> Result<usize, Error> {
    values_per_run(n_makers)?
        .checked_add(4)
        .and_then(|values| values.checked_add(3 * amount_bits))
        .and_then(|values| values.checked_add(3 * price_bits))
        .and_then(|values| values.checked_add(2 + 3 * price_bits))
        .ok_or_else(|| Error::Invalid("zkPI persistence wire count overflow".into()))
}

fn dvp_values_per_run(
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
) -> Result<usize, Error> {
    if remainder_bits == 0 {
        return Err(Error::Invalid(
            "DvP remainder width must be positive".into(),
        ));
    }
    zkpi_values_per_run(n_makers, amount_bits, price_bits)?
        // cash value + cash blinding + product cross relation
        .checked_add(3)
        .and_then(|values| values.checked_add(2 + 3 * remainder_bits))
        .and_then(|values| values.checked_add(2 + 3 * remainder_bits))
        .and_then(|values| values.checked_add(2 + 3 * remainder_bits))
        .ok_or_else(|| Error::Invalid("DvP persistence wire count overflow".into()))
}

pub fn quote_proof_values_per_run(
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    eligibility_bits: usize,
    span_bits: usize,
) -> Result<usize, Error> {
    if eligibility_bits == 0 || span_bits == 0 {
        return Err(Error::Invalid(
            "quote-proof range widths must be positive".into(),
        ));
    }
    // use_ref + 9 registered blindings + 10 derived blindings + 11 cross
    // relations + two (value, blinding, bit triples) eligibility ranges + key
    // blinding + one minimality range.
    let per_maker =
        38_usize
            .checked_add(6_usize.checked_mul(eligibility_bits).ok_or_else(|| {
                Error::Invalid("quote-proof eligibility wire count overflow".into())
            })?)
            .and_then(|value| value.checked_add(3_usize.checked_mul(span_bits)?))
            .ok_or_else(|| Error::Invalid("quote-proof wire count overflow".into()))?;
    dvp_values_per_run(n_makers, amount_bits, price_bits, remainder_bits)?
        .checked_add(
            n_makers
                .checked_mul(per_maker)
                .ok_or_else(|| Error::Invalid("quote-proof wire count overflow".into()))?,
        )
        .ok_or_else(|| Error::Invalid("quote-proof persistence wire count overflow".into()))
}

fn selected_run_offset(
    total: usize,
    per_run: usize,
    run: isize,
    path: &Path,
) -> Result<usize, Error> {
    if !total.is_multiple_of(per_run) {
        return Err(Error::Invalid(format!(
            "{} contains {total} values, which is not a whole number of {per_run}-value persistence runs",
            path.display()
        )));
    }
    let runs = total / per_run;
    let selected = if run >= 0 {
        usize::try_from(run).ok().filter(|index| *index < runs)
    } else {
        runs.checked_sub(run.unsigned_abs())
    }
    .ok_or_else(|| {
        Error::Invalid(format!(
            "run {run} of {runs} in {}: there is no such block",
            path.display()
        ))
    })?;
    Ok(selected * per_run)
}

/// Read exactly one node's MPC-produced zkPI shares.
///
/// A deployment invokes this inside each node's filesystem/security boundary.
/// Public Pedersen evaluations are exchanged later; the raw values returned
/// here must never be sent to an assembler or another node.
pub fn read_local_zkpi_handoff(
    path: impl AsRef<Path>,
    party: usize,
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    run: isize,
) -> Result<LocalZkpiHandoff, Error> {
    if amount_bits == 0 || price_bits == 0 {
        return Err(Error::Invalid(
            "zkPI amount and price widths must be positive".into(),
        ));
    }
    let per_run = zkpi_values_per_run(n_makers, amount_bits, price_bits)?;
    read_local_zkpi_handoff_with_stride(
        path,
        party,
        n_makers,
        amount_bits,
        price_bits,
        per_run,
        run,
    )
}

/// Read the zkPI prefix from a product circuit that appends DvP proof wires to
/// every persistence block. Treating the whole block as a zkPI-only run shifts
/// later runs and previously caused a valid 438-value product handoff to be
/// rejected as a malformed 241-value zkPI file.
pub fn read_local_zkpi_handoff_from_dvp(
    path: impl AsRef<Path>,
    party: usize,
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    run: isize,
) -> Result<LocalZkpiHandoff, Error> {
    if amount_bits == 0 || price_bits == 0 || remainder_bits == 0 {
        return Err(Error::Invalid(
            "zkPI and DvP range widths must be positive".into(),
        ));
    }
    let per_run = dvp_values_per_run(n_makers, amount_bits, price_bits, remainder_bits)?;
    read_local_zkpi_handoff_with_stride(
        path,
        party,
        n_makers,
        amount_bits,
        price_bits,
        per_run,
        run,
    )
}

/// Read the zkPI prefix from the complete product-plus-quote persistence ABI.
#[allow(clippy::too_many_arguments)]
pub fn read_local_zkpi_handoff_from_quote(
    path: impl AsRef<Path>,
    party: usize,
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    eligibility_bits: usize,
    span_bits: usize,
    run: isize,
) -> Result<LocalZkpiHandoff, Error> {
    let per_run = quote_proof_values_per_run(
        n_makers,
        amount_bits,
        price_bits,
        remainder_bits,
        eligibility_bits,
        span_bits,
    )?;
    read_local_zkpi_handoff_with_stride(
        path,
        party,
        n_makers,
        amount_bits,
        price_bits,
        per_run,
        run,
    )
}

#[allow(clippy::too_many_arguments)]
fn read_local_zkpi_handoff_with_stride(
    path: impl AsRef<Path>,
    party: usize,
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    per_run: usize,
    run: isize,
) -> Result<LocalZkpiHandoff, Error> {
    let path = path.as_ref();
    let file = read(path, party)?;
    let offset = selected_run_offset(file.shares.len(), per_run, run, path)?;
    let decode = |index: usize| -> Result<FieldElement, Error> {
        let stored = &file.shares[offset + index];
        if file.montgomery {
            from_montgomery(stored, &file.prime, file.element_bytes)
        } else {
            Ok(stored.clone())
        }
    };
    let base = values_per_run(n_makers)?;
    let winner_key_share = decode(0)?;
    let amount_value = decode(1)?;
    let maker_handle_share = decode(base)?;
    let price_value = decode(base + 1)?;
    let amount_blinding = decode(base + 2)?;
    let price_blinding = decode(base + 3)?;
    let mut cursor = base + 4;
    let mut amount = Vec::with_capacity(amount_bits);
    for _ in 0..amount_bits {
        amount.push((decode(cursor)?, decode(cursor + 1)?, decode(cursor + 2)?));
        cursor += 3;
    }
    let mut price = Vec::with_capacity(price_bits);
    for _ in 0..price_bits {
        price.push((decode(cursor)?, decode(cursor + 1)?, decode(cursor + 2)?));
        cursor += 3;
    }
    let limit_value = decode(cursor)?;
    let limit_blinding = decode(cursor + 1)?;
    cursor += 2;
    let mut price_limit_difference = Vec::with_capacity(price_bits);
    for _ in 0..price_bits {
        price_limit_difference.push((decode(cursor)?, decode(cursor + 1)?, decode(cursor + 2)?));
        cursor += 3;
    }
    if cursor > per_run {
        return Err(Error::Invalid(
            "internal zkPI persistence layout exceeds its run stride".into(),
        ));
    }
    Ok(LocalZkpiHandoff {
        party,
        path: path.to_path_buf(),
        prime: file.prime,
        winner_key_share,
        maker_handle_share,
        amount: LocalRangeHandoff {
            value_share: amount_value,
            blinding_share: amount_blinding,
            bits: amount,
        },
        price: LocalRangeHandoff {
            value_share: price_value,
            blinding_share: price_blinding,
            bits: price,
        },
        price_limit_difference: LocalRangeHandoff {
            value_share: limit_value,
            blinding_share: limit_blinding,
            bits: price_limit_difference,
        },
        runs_in_file: file.shares.len() / per_run,
    })
}

/// Read the DvP shares written by one MP-SPDZ party.  Callers invoke this in
/// the party's own storage boundary; there is intentionally no directory-wide
/// aggregate reader.
pub fn read_local_dvp_handoff(
    path: impl AsRef<Path>,
    party: usize,
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    run: isize,
) -> Result<LocalDvpHandoff, Error> {
    let per_run = dvp_values_per_run(n_makers, amount_bits, price_bits, remainder_bits)?;
    read_local_dvp_handoff_with_stride(
        path,
        party,
        n_makers,
        amount_bits,
        price_bits,
        remainder_bits,
        per_run,
        run,
    )
}

/// Read the DvP prefix from the complete product-plus-quote persistence ABI.
#[allow(clippy::too_many_arguments)]
pub fn read_local_dvp_handoff_from_quote(
    path: impl AsRef<Path>,
    party: usize,
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    eligibility_bits: usize,
    span_bits: usize,
    run: isize,
) -> Result<LocalDvpHandoff, Error> {
    let per_run = quote_proof_values_per_run(
        n_makers,
        amount_bits,
        price_bits,
        remainder_bits,
        eligibility_bits,
        span_bits,
    )?;
    read_local_dvp_handoff_with_stride(
        path,
        party,
        n_makers,
        amount_bits,
        price_bits,
        remainder_bits,
        per_run,
        run,
    )
}

#[allow(clippy::too_many_arguments)]
fn read_local_dvp_handoff_with_stride(
    path: impl AsRef<Path>,
    party: usize,
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    per_run: usize,
    run: isize,
) -> Result<LocalDvpHandoff, Error> {
    let path = path.as_ref();
    let file = read(path, party)?;
    let offset = selected_run_offset(file.shares.len(), per_run, run, path)?;
    let decode = |index: usize| -> Result<FieldElement, Error> {
        let stored = &file.shares[offset + index];
        if file.montgomery {
            from_montgomery(stored, &file.prime, file.element_bytes)
        } else {
            Ok(stored.clone())
        }
    };
    let base = values_per_run(n_makers)?;
    let price_share = decode(base + 1)?;
    let price_blinding_share = decode(base + 3)?;
    let mut cursor = zkpi_values_per_run(n_makers, amount_bits, price_bits)?;
    let cash_value_share = decode(cursor)?;
    let cash_blinding_share = decode(cursor + 1)?;
    let product_cross_share = decode(cursor + 2)?;
    cursor += 3;
    let read_range = |cursor: &mut usize| -> Result<LocalRangeHandoff, Error> {
        let value_share = decode(*cursor)?;
        let blinding_share = decode(*cursor + 1)?;
        *cursor += 2;
        let mut bits = Vec::with_capacity(remainder_bits);
        for _ in 0..remainder_bits {
            bits.push((decode(*cursor)?, decode(*cursor + 1)?, decode(*cursor + 2)?));
            *cursor += 3;
        }
        Ok(LocalRangeHandoff {
            value_share,
            blinding_share,
            bits,
        })
    };
    let securities_remainder = read_range(&mut cursor)?;
    let cash_remainder = read_range(&mut cursor)?;
    let maker_pool_remainder = read_range(&mut cursor)?;
    // `per_run` is the stride of the containing persistence ABI.  For the
    // product+quote ABI it also includes the quote-proof suffix, so comparing
    // the DvP prefix cursor with the full stride incorrectly rejects every
    // otherwise valid complete handoff.  Validate the prefix against its own
    // ABI boundary while retaining the full stride for run selection above.
    let dvp_end = dvp_values_per_run(n_makers, amount_bits, price_bits, remainder_bits)?;
    if cursor != dvp_end || dvp_end > per_run {
        return Err(Error::Invalid(
            "internal DvP persistence layout mismatch".into(),
        ));
    }
    Ok(LocalDvpHandoff {
        party,
        path: path.to_path_buf(),
        prime: file.prime,
        price_share,
        price_blinding_share,
        cash_value_share,
        cash_blinding_share,
        product_cross_share,
        securities_remainder,
        cash_remainder,
        maker_pool_remainder,
        runs_in_file: file.shares.len() / per_run,
    })
}

/// Read one node's complete quote-proof suffix and the quantity prefix it is
/// bound to. No directory-wide helper exists: each proof process calls this on
/// its own Persistence file.
#[allow(clippy::too_many_arguments)]
pub fn read_local_quote_proof_handoff(
    path: impl AsRef<Path>,
    party: usize,
    n_makers: usize,
    amount_bits: usize,
    price_bits: usize,
    remainder_bits: usize,
    eligibility_bits: usize,
    span_bits: usize,
    run: isize,
) -> Result<LocalQuoteProofHandoff, Error> {
    let path = path.as_ref();
    let file = read(path, party)?;
    let per_run = quote_proof_values_per_run(
        n_makers,
        amount_bits,
        price_bits,
        remainder_bits,
        eligibility_bits,
        span_bits,
    )?;
    let offset = selected_run_offset(file.shares.len(), per_run, run, path)?;
    let decode = |index: usize| -> Result<FieldElement, Error> {
        let stored = &file.shares[offset + index];
        if file.montgomery {
            from_montgomery(stored, &file.prime, file.element_bytes)
        } else {
            Ok(stored.clone())
        }
    };
    let qty_share = decode(1)?;
    let qty_blinding_share = decode(values_per_run(n_makers)? + 2)?;
    let mut cursor = dvp_values_per_run(n_makers, amount_bits, price_bits, remainder_bits)?;
    let read_named = |cursor: &mut usize,
                      names: &[&'static str]|
     -> Result<BTreeMap<&'static str, FieldElement>, Error> {
        let mut values = BTreeMap::new();
        for name in names {
            values.insert(*name, decode(*cursor)?);
            *cursor += 1;
        }
        Ok(values)
    };
    let read_range = |cursor: &mut usize, width: usize| -> Result<LocalRangeHandoff, Error> {
        let value_share = decode(*cursor)?;
        let blinding_share = decode(*cursor + 1)?;
        *cursor += 2;
        let mut bits = Vec::with_capacity(width);
        for _ in 0..width {
            bits.push((decode(*cursor)?, decode(*cursor + 1)?, decode(*cursor + 2)?));
            *cursor += 3;
        }
        Ok(LocalRangeHandoff {
            value_share,
            blinding_share,
            bits,
        })
    };
    let mut makers = Vec::with_capacity(n_makers);
    for _ in 0..n_makers {
        let maker_index = makers.len();
        let core_base = HEADER_NAMES.len() + maker_index * WIRE_NAMES.len();
        let mut core_wire_shares = BTreeMap::new();
        for (wire, name) in WIRE_NAMES.iter().enumerate() {
            core_wire_shares.insert(*name, decode(core_base + wire)?);
        }
        let use_ref_share = decode(cursor)?;
        cursor += 1;
        let policy_blinding_shares = read_named(&mut cursor, &QUOTE_POLICY_BLINDING_NAMES)?;
        let derived_blinding_shares = read_named(&mut cursor, &QUOTE_DERIVED_BLINDING_NAMES)?;
        let cross_shares = read_named(&mut cursor, &QUOTE_CROSS_NAMES)?;
        let fits_witness = read_range(&mut cursor, eligibility_bits)?;
        let fresh_witness = read_range(&mut cursor, eligibility_bits)?;
        let key_blinding_share = decode(cursor)?;
        cursor += 1;
        let minimality = read_range(&mut cursor, span_bits)?;
        makers.push(LocalQuoteMakerHandoff {
            core_wire_shares,
            use_ref_share,
            policy_blinding_shares,
            derived_blinding_shares,
            cross_shares,
            fits_witness,
            fresh_witness,
            key_blinding_share,
            minimality,
        });
    }
    if cursor != per_run {
        return Err(Error::Invalid(format!(
            "quote-proof persistence layout ended at {cursor}, expected {per_run}"
        )));
    }
    Ok(LocalQuoteProofHandoff {
        party,
        path: path.to_path_buf(),
        prime: file.prime,
        qty_share,
        qty_blinding_share,
        makers,
        runs_in_file: file.shares.len() / per_run,
    })
}

fn read_u32_le(bytes: &[u8], offset: usize, what: &str) -> Result<u32, Error> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::Invalid(format!("overflow while reading {what}")))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| Error::Invalid(format!("truncated {what}")))?
        .try_into()
        .expect("four-byte slice");
    Ok(u32::from_le_bytes(raw))
}

fn read_u64_le(bytes: &[u8], offset: usize, what: &str) -> Result<u64, Error> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Error::Invalid(format!("overflow while reading {what}")))?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or_else(|| Error::Invalid(format!("truncated {what}")))?
        .try_into()
        .expect("eight-byte slice");
    Ok(u64::from_le_bytes(raw))
}

/// Parse the length-prefixed field header at the start of a Persistence file.
pub fn parse_header(raw: &[u8]) -> Result<Header, Error> {
    let header_bytes = usize::try_from(read_u64_le(raw, 0, "header length")?)
        .map_err(|_| Error::Invalid("header length does not fit this platform".into()))?;
    let data_offset = 8_usize
        .checked_add(header_bytes)
        .ok_or_else(|| Error::Invalid("header length overflow".into()))?;
    let header = raw
        .get(8..data_offset)
        .ok_or_else(|| Error::Invalid("truncated Persistence header".into()))?;
    if !header.starts_with(b"Shamir gfp") {
        return Err(Error::Invalid(format!(
            "not a Shamir gfp persistence file ({:?})",
            &header[..header.len().min(16)]
        )));
    }
    let sign = *header
        .get(SIGN_OFFSET)
        .ok_or_else(|| Error::Invalid("truncated prime sign".into()))?;
    let negative = match sign {
        0 => false,
        1 => true,
        value => {
            return Err(Error::Invalid(format!(
                "invalid prime sign byte {value}; expected 0 or 1"
            )))
        }
    };
    let prime_bytes = read_u32_le(header, LENGTH_OFFSET, "prime byte length")? as usize;
    if prime_bytes == 0 {
        return Err(Error::Invalid(
            "the header declares a zero-byte prime".into(),
        ));
    }
    let prime_end = PRIME_OFFSET
        .checked_add(prime_bytes)
        .ok_or_else(|| Error::Invalid("prime byte length overflow".into()))?;
    let prime_raw = header
        .get(PRIME_OFFSET..prime_end)
        .ok_or_else(|| Error::Invalid("truncated prime".into()))?;
    let prime = FieldElement::from_bytes_be(prime_raw);
    if prime.bit_length() == 0 {
        return Err(Error::Invalid("the header declares a zero prime".into()));
    }
    let montgomery = read_u32_le(header, prime_end, "Montgomery flag")? != 0;
    let limbs = prime.bit_length().div_ceil(64);
    let element_bytes = limbs
        .checked_mul(LIMB_BYTES)
        .ok_or_else(|| Error::Invalid("field element width overflow".into()))?;
    Ok(Header {
        name: header[..NAME_BYTES].try_into().expect("ten-byte type name"),
        negative,
        prime,
        montgomery,
        element_bytes,
        header_bytes,
        data_offset,
    })
}

/// Read one zero-based party's file without reconstructing its shares.
pub fn read(path: impl AsRef<Path>, party: usize) -> Result<Persisted, Error> {
    let path = path.as_ref();
    let raw = fs::read(path)?;
    let header = parse_header(&raw).map_err(|error| match error {
        Error::Invalid(message) => Error::Invalid(format!("{}: {message}", path.display())),
        other => other,
    })?;
    let body = &raw[header.data_offset..];
    if body.len() % header.element_bytes != 0 {
        return Err(Error::Invalid(format!(
            "{}: {} bytes is not a whole number of {}-byte shares",
            path.display(),
            body.len(),
            header.element_bytes
        )));
    }
    let mut shares = Vec::with_capacity(body.len() / header.element_bytes);
    for (index, bytes) in body.chunks_exact(header.element_bytes).enumerate() {
        let value = FieldElement::from_bytes_le(bytes);
        if value >= header.prime {
            return Err(Error::Invalid(format!(
                "{}: a share at offset {} is not reduced; the file is not what this reader thinks it is",
                path.display(),
                index * header.element_bytes
            )));
        }
        shares.push(value);
    }
    Ok(Persisted {
        party,
        path: path.to_path_buf(),
        prime: header.prime,
        element_bytes: header.element_bytes,
        shares,
        montgomery: header.montgomery,
    })
}

fn subtract_assign(left: &mut Vec<u64>, right: &[u64]) {
    let mut borrow = 0_u128;
    for (index, item) in left.iter_mut().enumerate() {
        let rhs = right.get(index).copied().unwrap_or(0) as u128 + borrow;
        let lhs = *item as u128;
        if lhs >= rhs {
            *item = (lhs - rhs) as u64;
            borrow = 0;
        } else {
            *item = ((1_u128 << 64) + lhs - rhs) as u64;
            borrow = 1;
        }
    }
    debug_assert_eq!(borrow, 0);
    normalize(left);
}

/// Convert an MP-SPDZ field element from Montgomery form using 64-bit limbs.
pub fn from_montgomery(
    value: &FieldElement,
    prime: &FieldElement,
    element_bytes: usize,
) -> Result<FieldElement, Error> {
    if element_bytes == 0 || !element_bytes.is_multiple_of(LIMB_BYTES) {
        return Err(Error::Invalid(format!(
            "invalid Montgomery element width {element_bytes}"
        )));
    }
    let width = element_bytes / LIMB_BYTES;
    let modulus = prime.padded_limbs(width);
    if modulus.first().copied().unwrap_or(0) & 1 == 0 {
        return Err(Error::Invalid(
            "Montgomery field modulus must be odd".into(),
        ));
    }

    // Newton iteration modulo 2^64, then negate for -p^-1 mod 2^64.
    let mut inverse = 1_u64;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2_u64.wrapping_sub(modulus[0].wrapping_mul(inverse)));
    }
    let n0 = inverse.wrapping_neg();
    let mut work = vec![0_u64; 2 * width + 2];
    for (target, source) in work.iter_mut().zip(&value.limbs) {
        *target = *source;
    }

    for offset in 0..width {
        let multiplier = work[offset].wrapping_mul(n0);
        let mut carry = 0_u128;
        for (index, modulus_limb) in modulus.iter().enumerate() {
            let position = offset + index;
            let sum = work[position] as u128 + multiplier as u128 * *modulus_limb as u128 + carry;
            work[position] = sum as u64;
            carry = sum >> 64;
        }
        let mut position = offset + width;
        while carry != 0 {
            let sum = work[position] as u128 + carry;
            work[position] = sum as u64;
            carry = sum >> 64;
            position += 1;
        }
        debug_assert_eq!(work[offset], 0);
    }

    let mut reduced = work[width..].to_vec();
    normalize(&mut reduced);
    let mut result = FieldElement { limbs: reduced };
    if result >= *prime {
        subtract_assign(&mut result.limbs, &modulus);
    }
    Ok(result)
}

fn values_per_run(n_makers: usize) -> Result<usize, Error> {
    n_makers
        .checked_mul(WIRE_NAMES.len())
        .and_then(|values| values.checked_add(HEADER_NAMES.len()))
        .ok_or_else(|| Error::Invalid("wire count overflow".into()))
}

/// Count the complete persisted runs in one party file.
pub fn runs_in_file(path: impl AsRef<Path>, n_makers: usize) -> Result<usize, Error> {
    let expected = values_per_run(n_makers)?;
    let file = read(path, 0)?;
    if file.shares.len() % expected != 0 {
        return Err(Error::Invalid(format!(
            "file contains {} values, which is not a whole number of {expected}-value runs",
            file.shares.len()
        )));
    }
    Ok(file.shares.len() / expected)
}

/// Read one run from every `Transactions-P{party}.data` in `directory`.
pub fn read_wires(
    directory: impl AsRef<Path>,
    parties: usize,
    n_makers: usize,
    run: isize,
) -> Result<Wires, Error> {
    let directory = directory.as_ref();
    let expected = values_per_run(n_makers)?;
    let files = (0..parties)
        .map(|party| read(directory.join(format!("Transactions-P{party}.data")), party))
        .collect::<Result<Vec<_>, _>>()?;
    let first = files
        .first()
        .ok_or_else(|| Error::Invalid("at least one party is required".into()))?;
    if files.iter().any(|file| file.prime != first.prime) {
        // Name the parties and their primes. `Persistence/` is shared mutable
        // state that nothing clears, so the usual cause is not two nodes
        // disagreeing but one run's files sitting next to another's, and
        // "the nodes did not write in the same field" sends the reader looking
        // for a protocol fault instead of at a directory listing.
        let seen = files
            .iter()
            .enumerate()
            .map(|(party, file)| format!("P{party}={}", file.prime))
            .collect::<Vec<_>>()
            .join(" ");
        return Err(Error::Invalid(format!(
            "the nodes did not write in the same field, which usually means \
             the Persistence directory holds files from more than one run: {seen}"
        )));
    }

    let mut offsets = Vec::with_capacity(files.len());
    for file in &files {
        if file.shares.len() % expected != 0 {
            return Err(Error::Invalid(format!(
                "party {} wrote {} values, which is not a whole number of {expected}-value runs: one side has a wire the other does not",
                file.party,
                file.shares.len()
            )));
        }
        let total = file.shares.len() / expected;
        let selected = if run >= 0 {
            usize::try_from(run).ok().filter(|index| *index < total)
        } else {
            total.checked_sub(run.unsigned_abs())
        }
        .ok_or_else(|| {
            Error::Invalid(format!(
                "run {run} of {total} in {}: there is no such block",
                directory.display()
            ))
        })?;
        offsets.push(selected * expected);
    }
    if files
        .windows(2)
        .any(|pair| pair[0].shares.len() != pair[1].shares.len())
    {
        return Err(Error::Invalid(
            "the nodes wrote different numbers of runs".into(),
        ));
    }

    let at = |index: usize| -> Result<BTreeMap<usize, FieldElement>, Error> {
        files
            .iter()
            .zip(&offsets)
            .map(|(file, offset)| {
                let stored = &file.shares[offset + index];
                let value = if file.montgomery {
                    from_montgomery(stored, &file.prime, file.element_bytes)?
                } else {
                    stored.clone()
                };
                Ok((file.party + 1, value))
            })
            .collect()
    };

    let mut makers = Vec::with_capacity(n_makers);
    for maker in 0..n_makers {
        let base = HEADER_NAMES.len() + maker * WIRE_NAMES.len();
        let mut wires = BTreeMap::new();
        for (index, &name) in WIRE_NAMES.iter().enumerate() {
            wires.insert(name, at(base + index)?);
        }
        makers.push(wires);
    }
    Ok(Wires {
        prime: first.prime.clone(),
        winner_key: at(0)?,
        qty: at(1)?,
        makers,
        runs_in_file: first.shares.len() / expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn decode_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("non-hex test vector"),
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect()
    }

    fn test_prime() -> (FieldElement, Vec<u8>) {
        let prime = (1_u128 << 89) - 1;
        let element = FieldElement::from_u128(prime);
        let bytes = prime.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        (element, bytes[first..].to_vec())
    }

    #[test]
    fn reads_one_nodes_zkpi_handoff_without_materializing_other_parties() {
        let directory = TestDir::new();
        let path = directory.0.join("Transactions-P0.data");
        let values = (1_u64..=49).collect::<Vec<_>>();
        fs::write(&path, encode_file(false, &values)).unwrap();

        let handoff = read_local_zkpi_handoff(&path, 0, 1, 2, 2, -1).unwrap();
        assert_eq!(handoff.party, 0);
        assert_eq!(handoff.winner_key_share, FieldElement::from_u64(1));
        assert_eq!(handoff.amount.value_share, FieldElement::from_u64(2));
        assert_eq!(handoff.maker_handle_share, FieldElement::from_u64(26));
        assert_eq!(handoff.price.value_share, FieldElement::from_u64(27));
        assert_eq!(handoff.amount.blinding_share, FieldElement::from_u64(28));
        assert_eq!(handoff.price.blinding_share, FieldElement::from_u64(29));
        assert_eq!(
            handoff.amount.bits[0],
            (
                FieldElement::from_u64(30),
                FieldElement::from_u64(31),
                FieldElement::from_u64(32)
            )
        );
        assert_eq!(
            handoff.price.bits[1],
            (
                FieldElement::from_u64(39),
                FieldElement::from_u64(40),
                FieldElement::from_u64(41)
            )
        );
        assert_eq!(
            handoff.price_limit_difference.value_share,
            FieldElement::from_u64(42)
        );
        assert_eq!(
            handoff.price_limit_difference.bits[1],
            (
                FieldElement::from_u64(47),
                FieldElement::from_u64(48),
                FieldElement::from_u64(49)
            )
        );
    }

    #[test]
    fn reads_one_nodes_dvp_handoff_without_materializing_other_parties() {
        let directory = TestDir::new();
        let path = directory.0.join("Transactions-P0.data");
        let per_run = dvp_values_per_run(1, 2, 2, 2).unwrap();
        let values = (1_u64..=per_run as u64).collect::<Vec<_>>();
        fs::write(&path, encode_file(false, &values)).unwrap();

        let handoff = read_local_dvp_handoff(&path, 0, 1, 2, 2, 2, -1).unwrap();
        let zkpi = read_local_zkpi_handoff_from_dvp(&path, 0, 1, 2, 2, 2, -1).unwrap();
        assert_eq!(zkpi.winner_key_share, FieldElement::from_u64(1));
        assert_eq!(zkpi.amount.value_share, FieldElement::from_u64(2));
        assert_eq!(zkpi.maker_handle_share, FieldElement::from_u64(26));
        assert_eq!(zkpi.price.value_share, FieldElement::from_u64(27));
        assert_eq!(handoff.party, 0);
        assert_eq!(handoff.price_share, FieldElement::from_u64(27));
        assert_eq!(handoff.price_blinding_share, FieldElement::from_u64(29));
        assert_eq!(
            zkpi.price_limit_difference.value_share,
            FieldElement::from_u64(42)
        );
        assert_eq!(handoff.cash_value_share, FieldElement::from_u64(50));
        assert_eq!(handoff.cash_blinding_share, FieldElement::from_u64(51));
        assert_eq!(handoff.product_cross_share, FieldElement::from_u64(52));
        assert_eq!(
            handoff.securities_remainder.value_share,
            FieldElement::from_u64(53)
        );
        assert_eq!(
            handoff.securities_remainder.bits[1],
            (
                FieldElement::from_u64(58),
                FieldElement::from_u64(59),
                FieldElement::from_u64(60)
            )
        );
        assert_eq!(
            handoff.cash_remainder.blinding_share,
            FieldElement::from_u64(62)
        );
        assert_eq!(
            handoff.cash_remainder.bits[1],
            (
                FieldElement::from_u64(66),
                FieldElement::from_u64(67),
                FieldElement::from_u64(68)
            )
        );
        assert_eq!(
            handoff.maker_pool_remainder.value_share,
            FieldElement::from_u64(69)
        );
        assert_eq!(
            handoff.maker_pool_remainder.blinding_share,
            FieldElement::from_u64(70)
        );
        assert_eq!(
            handoff.maker_pool_remainder.bits[1],
            (
                FieldElement::from_u64(74),
                FieldElement::from_u64(75),
                FieldElement::from_u64(76)
            )
        );
    }

    #[test]
    fn reads_dvp_prefix_from_complete_quote_persistence_stride() {
        let directory = TestDir::new();
        let path = directory.0.join("Transactions-P0.data");
        let per_run = quote_proof_values_per_run(1, 2, 2, 2, 2, 2).unwrap();
        let values = (1_u64..=per_run as u64).collect::<Vec<_>>();
        fs::write(&path, encode_file(false, &values)).unwrap();

        let handoff = read_local_dvp_handoff_from_quote(&path, 0, 1, 2, 2, 2, 2, 2, -1).unwrap();
        assert_eq!(handoff.runs_in_file, 1);
        assert_eq!(handoff.cash_value_share, FieldElement::from_u64(50));
        assert_eq!(handoff.cash_blinding_share, FieldElement::from_u64(51));
        assert_eq!(handoff.product_cross_share, FieldElement::from_u64(52));
        assert_eq!(
            handoff.cash_remainder.bits[1],
            (
                FieldElement::from_u64(66),
                FieldElement::from_u64(67),
                FieldElement::from_u64(68)
            )
        );
    }

    fn encode_file(montgomery: bool, values: &[u64]) -> Vec<u8> {
        let (_, prime_bytes) = test_prime();
        let mut header = Vec::new();
        header.extend_from_slice(b"Shamir gfp");
        header.push(0);
        header.extend_from_slice(&(prime_bytes.len() as u32).to_le_bytes());
        header.extend_from_slice(&prime_bytes);
        header.extend_from_slice(&(montgomery as u32).to_le_bytes());

        let mut raw = Vec::new();
        raw.extend_from_slice(&(header.len() as u64).to_le_bytes());
        raw.extend_from_slice(&header);
        for value in values {
            // For p=2^89-1 and a 16-byte element, R=2^128=2^39 mod p.
            let stored = if montgomery {
                FieldElement::from_u128((*value as u128) << 39)
            } else {
                FieldElement::from_u64(*value)
            };
            raw.extend_from_slice(&stored.to_bytes_le(16).unwrap());
        }
        raw
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            // macOS may expose the same SystemTime value to tests that begin in
            // parallel.  Include a process-local sequence so every test owns a
            // distinct Persistence directory even at coarse clock resolution.
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "qomm-persistence-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_mp_spdz_header_and_limb_width() {
        let (prime, _) = test_prime();
        let raw = encode_file(true, &[17]);
        let header = parse_header(&raw).unwrap();
        assert_eq!(&header.name, b"Shamir gfp");
        assert_eq!(header.prime, prime);
        assert!(header.montgomery);
        assert_eq!(header.element_bytes, 16);
        assert_eq!(header.data_offset, raw.len() - 16);
    }

    #[test]
    fn parses_checked_in_real_mp_spdz_persistence() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/persistence/Transactions-P0.data");
        let file = read(path, 0).unwrap();
        assert_eq!(
            file.prime.to_string(),
            "170141183460469231731687303715885907969"
        );
        assert_eq!(file.element_bytes, 16);
        assert!(file.montgomery);
        assert_eq!(file.shares.len(), 1);
        assert_eq!(
            from_montgomery(&file.shares[0], &file.prime, file.element_bytes)
                .unwrap()
                .to_string(),
            "149431406576252675492646689489243200149"
        );
    }

    #[test]
    fn reads_two_synthetic_runs_and_removes_montgomery_form() {
        let directory = TestDir::new();
        let per_run = HEADER_NAMES.len() + WIRE_NAMES.len();
        for party in 0..2 {
            let values = (0..2 * per_run)
                .map(|index| 1 + index as u64 + 100 * party as u64)
                .collect::<Vec<_>>();
            fs::write(
                directory.0.join(format!("Transactions-P{party}.data")),
                encode_file(true, &values),
            )
            .unwrap();
        }

        assert_eq!(
            runs_in_file(directory.0.join("Transactions-P0.data"), 1).unwrap(),
            2
        );
        let wires = read_wires(&directory.0, 2, 1, -1).unwrap();
        assert_eq!(wires.runs_in_file, 2);
        assert_eq!(wires.winner_key[&1].as_u128(), Some(26));
        assert_eq!(wires.winner_key[&2].as_u128(), Some(126));
        assert_eq!(wires.qty[&1].as_u128(), Some(27));
        assert_eq!(wires.makers[0]["ask_level"][&1].as_u128(), Some(28));
        assert_eq!(wires.makers[0]["cost"][&2].as_u128(), Some(150));
    }

    #[test]
    fn leaves_non_montgomery_values_unchanged() {
        let directory = TestDir::new();
        let values = (1..=(HEADER_NAMES.len() + WIRE_NAMES.len()) as u64).collect::<Vec<_>>();
        fs::write(
            directory.0.join("Transactions-P0.data"),
            encode_file(false, &values),
        )
        .unwrap();
        let wires = read_wires(&directory.0, 1, 1, 0).unwrap();
        assert_eq!(wires.winner_key[&1].as_u128(), Some(1));
        assert_eq!(wires.makers[0]["cost"][&1].as_u128(), Some(25));
    }

    #[test]
    fn arbitrary_width_decimal_display_is_exact() {
        let value =
            FieldElement::from_bytes_be(&[0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(value.to_string(), "21267647932558653966460912964485513217");
    }

    #[test]
    fn removes_montgomery_form_in_the_253_bit_shamir_field() {
        let prime = FieldElement::from_bytes_be(&decode_hex(
            "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        ));
        let stored_one = FieldElement::from_bytes_le(&decode_hex(
            "1d95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f",
        ));
        let stored_42 = FieldElement::from_bytes_le(&decode_hex(
            "cd85a957e63dce272feafbd872118f4bc9ffffffffffffffffffffffffffff0f",
        ));
        assert_eq!(
            from_montgomery(&stored_one, &prime, 32).unwrap(),
            FieldElement::from_u64(1)
        );
        assert_eq!(
            from_montgomery(&stored_42, &prime, 32).unwrap(),
            FieldElement::from_u64(42)
        );
    }
}
