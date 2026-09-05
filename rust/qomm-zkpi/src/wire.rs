//! The bytes a zero-knowledge payment instruction travels as.
//!
//! An instruction is meant to be accepted by a venue that did not issue it and
//! does not run this code --- that is what "deliberately pluggable" has to mean
//! before it means anything. A struct in one language is not an interface. So:
//! a byte layout, a version in front of it, vectors somebody else can check
//! their implementation against, and a verifier that reads the bytes and says
//! yes or no with nothing else in the process.
//!
//! # Layout
//!
//! Every field is fixed-width or length-prefixed, big-endian throughout, and
//! the order below is the order on the wire. Nothing is optional: an
//! instruction with a field missing is not a shorter instruction, it is not an
//! instruction.
//!
//! ```text
//! magic            8   "QOMMZKPI"
//! version          2   currently 2
//! amount_commit   32   compressed Ristretto
//! price_commit    32
//! asset_commit    32
//! payer_handle    32
//! payee_handle    32
//! deadline         8   seconds since the Unix epoch
//! nonce           32
//! quote_proof      32   SHA-256 digest of the complete public quote proof
//! signature       64   FROST over Ristretto255
//! amount_len       4
//! amount_range   amount_len   jointly assembled threshold range proof
//! price_len        4
//! price_range    price_len    jointly assembled threshold range proof
//! ```
//!
//! Version 1 is retained only as an explicitly tagged compatibility format. It
//! carries an 8-byte packed quote key and two Bulletproofs. The product path
//! emits version 2, which reveals neither the packed winner nor the price and
//! binds the instruction to the complete public quote-proof digest.
//!
//! # What the version is for
//!
//! Refusing, not negotiating. A verifier that meets a version it does not know
//! stops --- it does not guess at a layout, because a misparsed commitment is a
//! valid point and would be checked against with confidence. The one thing
//! worse than rejecting a payment is settling a different one.
//!
//! # What is not here
//!
//! No compression, no self-describing container, no forward compatibility.
//! Every one of those is a way for two implementations to disagree about what
//! they read, and this format is small enough that a second implementation is a
//! day's work from the table above.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use frost_ristretto255 as frost;
use qomm_proofs::threshold_range::ThresholdRangeProof;
use qomm_zk::sigma::{OpeningProof, ProductProof};

use crate::{Instruction, QuoteBinding, RangeEvidence};

pub const MAGIC: &[u8; 8] = b"QOMMZKPI";
pub const LEGACY_VERSION: u16 = 1;
pub const VERSION: u16 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    NotAnInstruction,
    /// A version this build does not know. Refused rather than guessed at: a
    /// misparsed commitment is still a valid point.
    UnknownVersion(u16),
    Truncated {
        wanted: usize,
        had: usize,
        at: &'static str,
    },
    NotAPoint(&'static str),
    BadScalar(&'static str),
    BadSignature,
    /// Bytes left over. An instruction is exactly as long as it is.
    Trailing(usize),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::NotAnInstruction => write!(f, "this does not begin QOMMZKPI"),
            WireError::UnknownVersion(v) => write!(
                f,
                "version {v}, and this build knows {LEGACY_VERSION} and {VERSION}. Refused rather \
                 than guessed at --- a misparsed commitment is a valid point."
            ),
            WireError::Truncated { wanted, had, at } => {
                write!(f, "{at}: wanted {wanted} bytes and {had} were left")
            }
            WireError::NotAPoint(what) => write!(f, "{what} is not a group element"),
            WireError::BadScalar(what) => write!(f, "{what} is not a canonical scalar"),
            WireError::BadSignature => write!(f, "the signature is not well formed"),
            WireError::Trailing(n) => write!(
                f,
                "{n} bytes after the end. An instruction is exactly as long as \
                 it is, so this is a different message."
            ),
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], WireError> {
        if self.bytes.len() - self.at < n {
            return Err(WireError::Truncated {
                wanted: n,
                had: self.bytes.len() - self.at,
                at: what,
            });
        }
        let slice = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(slice)
    }

    fn point(&mut self, what: &'static str) -> Result<RistrettoPoint, WireError> {
        let bytes: [u8; 32] = self.take(32, what)?.try_into().unwrap();
        CompressedRistretto(bytes)
            .decompress()
            .ok_or(WireError::NotAPoint(what))
    }

    fn scalar(&mut self, what: &'static str) -> Result<Scalar, WireError> {
        let bytes: [u8; 32] = self.take(32, what)?.try_into().unwrap();
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .ok_or(WireError::BadScalar(what))
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.take(8, what)?.try_into().unwrap()))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4, what)?.try_into().unwrap()))
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take(2, what)?.try_into().unwrap()))
    }
}

pub fn encode(instruction: &Instruction) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(MAGIC);
    let version = match (&instruction.ranges, &instruction.quote_binding) {
        (RangeEvidence::Bulletproof { .. }, QuoteBinding::LegacyPackedKey(_)) => LEGACY_VERSION,
        (RangeEvidence::Threshold { .. }, QuoteBinding::ProofDigest(_)) => VERSION,
        _ => panic!("zkPI range evidence and quote binding belong to different wire versions"),
    };
    out.extend_from_slice(&version.to_be_bytes());
    for point in [
        &instruction.amount_commitment,
        &instruction.price_commitment,
        &instruction.asset_commitment,
        &instruction.payer_handle,
        &instruction.payee_handle,
    ] {
        out.extend_from_slice(point.compress().as_bytes());
    }
    out.extend_from_slice(&instruction.deadline.to_be_bytes());
    out.extend_from_slice(&instruction.nonce);
    match &instruction.quote_binding {
        QuoteBinding::LegacyPackedKey(value) => out.extend_from_slice(&value.to_be_bytes()),
        QuoteBinding::ProofDigest(value) => out.extend_from_slice(value),
    }
    out.extend_from_slice(
        &instruction
            .signature
            .serialize()
            .expect("a FROST signature serialises"),
    );
    match &instruction.ranges {
        RangeEvidence::Bulletproof {
            amount,
            price,
            commitments,
        } => {
            out.extend_from_slice(&(commitments.len() as u16).to_be_bytes());
            for commitment in commitments {
                out.extend_from_slice(commitment.as_bytes());
            }
            for proof in [amount, price] {
                let bytes = proof.to_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
        }
        RangeEvidence::Threshold { amount, price } => {
            for proof in [amount, price] {
                let bytes = encode_threshold_range(proof);
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
        }
    }
    out
}

pub fn threshold_range_encoded_len(proof: &ThresholdRangeProof) -> usize {
    // width + one commitment and one five-element product proof per bit,
    // followed by the three-element linkage opening.
    2 + proof.bit_commitments.len() * (32 + 5 * 32) + 3 * 32
}

/// Canonical generic threshold-range proof encoding for application bindings.
pub fn encode_threshold_range(proof: &ThresholdRangeProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(threshold_range_encoded_len(proof));
    let bits = u16::try_from(proof.bits).expect("threshold range width fits u16");
    out.extend_from_slice(&bits.to_be_bytes());
    for (commitment, product) in proof.bit_commitments.iter().zip(&proof.bit_proofs) {
        out.extend_from_slice(commitment.compress().as_bytes());
        out.extend_from_slice(product.t_factor.compress().as_bytes());
        out.extend_from_slice(product.t_product.compress().as_bytes());
        out.extend_from_slice(&product.z_b.to_bytes());
        out.extend_from_slice(&product.z_rb.to_bytes());
        out.extend_from_slice(&product.z_s.to_bytes());
    }
    out.extend_from_slice(proof.linkage.t.compress().as_bytes());
    out.extend_from_slice(&proof.linkage.z_value.to_bytes());
    out.extend_from_slice(&proof.linkage.z_blinding.to_bytes());
    out
}

/// Decode a canonical generic threshold-range proof.
pub fn decode_threshold_range(raw: &[u8]) -> Result<ThresholdRangeProof, WireError> {
    let mut r = Reader { bytes: raw, at: 0 };
    let bits = r.u16("threshold range width")? as usize;
    let mut bit_commitments = Vec::with_capacity(bits);
    let mut bit_proofs = Vec::with_capacity(bits);
    for _ in 0..bits {
        bit_commitments.push(r.point("threshold bit commitment")?);
        bit_proofs.push(ProductProof {
            t_factor: r.point("threshold bit factor nonce")?,
            t_product: r.point("threshold bit product nonce")?,
            z_b: r.scalar("threshold bit value response")?,
            z_rb: r.scalar("threshold bit blinding response")?,
            z_s: r.scalar("threshold bit relation response")?,
        });
    }
    let linkage = OpeningProof {
        t: r.point("threshold range linkage nonce")?,
        z_value: r.scalar("threshold range linkage value response")?,
        z_blinding: r.scalar("threshold range linkage blinding response")?,
    };
    if r.at != raw.len() {
        return Err(WireError::Trailing(raw.len() - r.at));
    }
    Ok(ThresholdRangeProof {
        bit_commitments,
        bit_proofs,
        linkage,
        bits,
    })
}

pub fn decode(bytes: &[u8]) -> Result<Instruction, WireError> {
    let mut r = Reader { bytes, at: 0 };
    if r.take(8, "magic")? != MAGIC {
        return Err(WireError::NotAnInstruction);
    }
    let version = r.u16("version")?;
    if version != LEGACY_VERSION && version != VERSION {
        return Err(WireError::UnknownVersion(version));
    }
    let amount_commitment = r.point("amount commitment")?;
    let price_commitment = r.point("price commitment")?;
    let asset_commitment = r.point("asset commitment")?;
    let payer_handle = r.point("payer handle")?;
    let payee_handle = r.point("payee handle")?;
    let deadline = r.u64("deadline")?;
    let nonce: [u8; 32] = r.take(32, "nonce")?.try_into().unwrap();
    let quote_binding = if version == LEGACY_VERSION {
        QuoteBinding::LegacyPackedKey(r.u64("quote key")?)
    } else {
        QuoteBinding::ProofDigest(r.take(32, "quote proof digest")?.try_into().unwrap())
    };
    let signature = frost::Signature::deserialize(r.take(64, "signature")?)
        .map_err(|_| WireError::BadSignature)?;
    let ranges = if version == LEGACY_VERSION {
        let count = r.u16("range commitment count")? as usize;
        let mut commitments = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes: [u8; 32] = r.take(32, "range commitment")?.try_into().unwrap();
            commitments.push(CompressedRistretto(bytes));
        }
        let mut proofs = Vec::with_capacity(2);
        for what in ["amount range proof", "price range proof"] {
            let len = r.u32(what)? as usize;
            let raw = r.take(len, what)?;
            proofs.push(
                bulletproofs::RangeProof::from_bytes(raw)
                    .map_err(|_| WireError::NotAPoint(what))?,
            );
        }
        let mut proofs = proofs.into_iter();
        RangeEvidence::Bulletproof {
            amount: proofs.next().unwrap(),
            price: proofs.next().unwrap(),
            commitments,
        }
    } else {
        let amount_len = r.u32("threshold amount range proof")? as usize;
        let amount = decode_threshold_range(r.take(amount_len, "threshold amount range proof")?)?;
        let price_len = r.u32("threshold price range proof")? as usize;
        let price = decode_threshold_range(r.take(price_len, "threshold price range proof")?)?;
        RangeEvidence::Threshold { amount, price }
    };
    if r.at != bytes.len() {
        return Err(WireError::Trailing(bytes.len() - r.at));
    }
    Ok(Instruction {
        amount_commitment,
        price_commitment,
        asset_commitment,
        ranges,
        payer_handle,
        payee_handle,
        deadline,
        nonce,
        quote_binding,
        signature,
    })
}

/// A vector another implementation can check itself against.
///
/// Vectors are the interface, not the struct. Two implementations that agree on
/// a table and disagree on a byte have not interoperated, and only fixed inputs
/// producing fixed bytes finds that out.
pub struct Vector {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub accepts: bool,
    pub why: &'static str,
}

/// The digest of an encoded instruction, so a vector can be quoted in one line.
pub fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"QOMM:ZKPI:WIRE:v1");
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The layout, as a table, so the specification is emitted rather than kept.
///
/// A document beside the code is a document that drifts from it. The field
/// widths below are the ones `encode` writes, because they are the same
/// constants.
pub fn spec() -> String {
    let mut out = String::new();
    out.push_str("# zkPI on the wire, version 2\n\n");
    out.push_str(
        "Big-endian throughout. Every field is fixed-width or \
length-prefixed, and the order below is the order on the wire. Nothing is \
optional: an instruction with a field missing is not a shorter instruction.\n\n",
    );
    out.push_str("| field | bytes | what |\n| --- | ---: | --- |\n");
    for (field, width, what) in [
        ("magic", "8", "`QOMMZKPI`"),
        ("version", "2", "currently 2. A verifier that meets one it does not know **stops** --- it does not guess at a layout, because a misparsed commitment is a valid point"),
        ("amount commitment", "32", "compressed Ristretto"),
        ("price commitment", "32", "compressed Ristretto"),
        ("asset commitment", "32", "compressed Ristretto"),
        ("payer handle", "32", "compressed Ristretto"),
        ("payee handle", "32", "compressed Ristretto"),
        ("deadline", "8", "seconds since the Unix epoch"),
        ("nonce", "32", "what makes the nullifier unique"),
        ("quote proof digest", "32", "SHA-256 digest of the complete public quote proof; it reveals neither the packed winner nor the price"),
        ("signature", "64", "FROST over Ristretto255"),
        ("amount proof length", "4", ""),
        ("amount range proof", "that many", "jointly assembled threshold range proof"),
        ("price proof length", "4", ""),
        ("price range proof", "that many", "jointly assembled threshold range proof"),
    ] {
        out.push_str(&format!("| {field} | {width} | {what} |\n"));
    }
    out.push_str("\n## Version 1 compatibility format\n\n");
    out.push_str(
        "Version 1 is still decoded and re-encoded when explicitly tagged as \
version 1. It carries an 8-byte packed quote key, a range-commitment count, \
the corresponding commitments, and two Bulletproofs. It is a migration \
format, not the product issuance path. Version 2 emits a 32-byte quote-proof \
digest and two jointly assembled threshold range proofs.\n",
    );
    out.push_str("\n## What is deliberately absent\n\n");
    out.push_str(
        "No compression, no self-describing container, no forward \
compatibility. Each is a way for two implementations to disagree about what \
they read, and the table above is a day's work to implement from.\n",
    );
    out
}
