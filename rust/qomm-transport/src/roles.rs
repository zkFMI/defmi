//! Input roles, signed dealing receipts, and entity-scoped rate limiting.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};

pub use qomm_proofs::kyb::{EntityLimits, EntityRateLimiter, Refused, Usage};

pub const SLACK_BITS: u32 = 40;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RoleError {
    #[error("sharing needs at least two nodes")]
    NodeCount,
    #[error("value needs {actual} bits, declared {declared}")]
    ValueWidth { actual: u32, declared: u32 },
    #[error("share range exceeds signed 128-bit arithmetic")]
    ShareWidth,
    #[error("a {field_bits}-bit field cannot hold {n_nodes} shares of a {value_bits}-bit value: {needed} bits are needed")]
    FieldWidth {
        n_nodes: usize,
        value_bits: u32,
        field_bits: u32,
        needed: u32,
    },
    #[error("dealing to a different number of nodes than declared")]
    NodeShape,
    #[error("party identifiers start at one")]
    PartyZero,
    #[error("modulus must be greater than every party identifier")]
    Modulus,
}

fn magnitude_bits(value: i128) -> u32 {
    if value == i128::MIN {
        128
    } else {
        let magnitude = value.unsigned_abs();
        128 - magnitude.leading_zeros()
    }
}

pub fn split(value: i128, n_nodes: usize, value_bits: u32) -> Result<Vec<i128>, RoleError> {
    split_with_rng(value, n_nodes, value_bits, &mut OsRng)
}

pub fn split_with_rng(
    value: i128,
    n_nodes: usize,
    value_bits: u32,
    rng: &mut impl RngCore,
) -> Result<Vec<i128>, RoleError> {
    if n_nodes < 2 {
        return Err(RoleError::NodeCount);
    }
    let actual = magnitude_bits(value);
    if actual > value_bits {
        return Err(RoleError::ValueWidth {
            actual,
            declared: value_bits,
        });
    }
    let width = value_bits
        .checked_add(SLACK_BITS)
        .ok_or(RoleError::ShareWidth)?;
    if width >= 126 {
        return Err(RoleError::ShareWidth);
    }
    let mask = (1_u128 << width) - 1;
    let mut shares = Vec::with_capacity(n_nodes);
    let mut total = 0_i128;
    for _ in 0..n_nodes - 1 {
        let random = (u128::from(rng.next_u64()) | (u128::from(rng.next_u64()) << 64)) & mask;
        let share = i128::try_from(random).map_err(|_| RoleError::ShareWidth)?;
        total = total.checked_add(share).ok_or(RoleError::ShareWidth)?;
        shares.push(share);
    }
    shares.push(value.checked_sub(total).ok_or(RoleError::ShareWidth)?);
    Ok(shares)
}

pub fn check_field_width(
    n_nodes: usize,
    value_bits: u32,
    field_bits: u32,
) -> Result<(), RoleError> {
    let node_bits = usize::BITS - n_nodes.saturating_sub(1).leading_zeros();
    let needed = value_bits + SLACK_BITS + node_bits + 2;
    if field_bits < needed {
        return Err(RoleError::FieldWidth {
            n_nodes,
            value_bits,
            field_bits,
            needed,
        });
    }
    Ok(())
}

fn add_mod(left: u128, right: u128, modulus: u128) -> u128 {
    if left >= modulus - right {
        left - (modulus - right)
    } else {
        left + right
    }
}

fn mul_mod(mut left: u128, mut right: u128, modulus: u128) -> u128 {
    let mut result = 0_u128;
    left %= modulus;
    while right != 0 {
        if right & 1 == 1 {
            result = add_mod(result, left, modulus);
        }
        right >>= 1;
        if right != 0 {
            left = add_mod(left, left, modulus);
        }
    }
    result
}

fn pow_mod(mut base: u128, mut exponent: u128, modulus: u128) -> u128 {
    let mut result = 1_u128;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        exponent >>= 1;
        if exponent != 0 {
            base = mul_mod(base, base, modulus);
        }
    }
    result
}

/// Public interpolation coefficients for the points `1..=n_nodes`.
pub fn lagrange_at_zero(n_nodes: usize, prime: u128) -> Result<Vec<u128>, RoleError> {
    if prime <= n_nodes as u128 || prime < 3 {
        return Err(RoleError::Modulus);
    }
    let mut coefficients = Vec::with_capacity(n_nodes);
    for point in 1..=n_nodes as u128 {
        let mut numerator = 1_u128;
        let mut denominator = 1_u128;
        for other in 1..=n_nodes as u128 {
            if other == point {
                continue;
            }
            numerator = mul_mod(numerator, prime - other, prime);
            let difference = if point >= other {
                point - other
            } else {
                prime - (other - point)
            };
            denominator = mul_mod(denominator, difference, prime);
        }
        coefficients.push(mul_mod(
            numerator,
            pow_mod(denominator, prime - 2, prime),
            prime,
        ));
    }
    Ok(coefficients)
}

pub fn shamir_split_with_rng(
    value: u128,
    n_nodes: usize,
    threshold: usize,
    prime: u128,
    rng: &mut impl RngCore,
) -> Result<Vec<u128>, RoleError> {
    if n_nodes < 2 * threshold + 1 {
        return Err(RoleError::NodeCount);
    }
    let mut coefficients = vec![value % prime];
    for _ in 0..threshold {
        let random = u128::from(rng.next_u64()) | (u128::from(rng.next_u64()) << 64);
        coefficients.push(random % prime);
    }
    Ok((1..=n_nodes as u128)
        .map(|point| {
            coefficients
                .iter()
                .rev()
                .fold(0_u128, |accumulator, coefficient| {
                    add_mod(mul_mod(accumulator, point, prime), *coefficient, prime)
                })
        })
        .collect())
}

fn signed_64(value: i128) -> [u8; 64] {
    let fill = if value < 0 { 0xff } else { 0 };
    let mut out = [fill; 64];
    out[48..].copy_from_slice(&value.to_be_bytes());
    out
}

pub fn dealt_body(dealer: &str, index: usize, position: usize, share: i128) -> Vec<u8> {
    let mut body = Vec::with_capacity(24 + dealer.len() + 64);
    body.extend_from_slice(b"QOMM:TRANSPORT:SHARE:v1");
    body.extend_from_slice(&(dealer.len() as u32).to_be_bytes());
    body.extend_from_slice(dealer.as_bytes());
    body.extend_from_slice(&(index as u32).to_be_bytes());
    body.extend_from_slice(&(position as u64).to_be_bytes());
    body.extend_from_slice(&signed_64(share));
    body
}

#[derive(Clone, Debug, Default)]
pub struct ComputingNode {
    pub index: usize,
    pub inputs: Vec<i128>,
    pub receipts: Vec<Option<Signature>>,
}

impl ComputingNode {
    pub fn new(index: usize) -> Self {
        Self {
            index,
            ..Self::default()
        }
    }

    pub fn receive(&mut self, share: i128, receipt: Option<Signature>) {
        self.inputs.push(share);
        self.receipts.push(receipt);
    }
}

pub struct InputParty {
    pub name: String,
    pub n_nodes: usize,
    pub value_bits: u32,
    pub signing_key: Option<SigningKey>,
}

impl InputParty {
    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        self.signing_key.as_ref().map(SigningKey::verifying_key)
    }

    pub fn deal(&self, values: &[i128], nodes: &mut [ComputingNode]) -> Result<(), RoleError> {
        if nodes.len() != self.n_nodes {
            return Err(RoleError::NodeShape);
        }
        for value in values {
            let shares = split(*value, self.n_nodes, self.value_bits)?;
            for (node, share) in nodes.iter_mut().zip(shares) {
                let position = node.inputs.len();
                let receipt = self
                    .signing_key
                    .as_ref()
                    .map(|key| key.sign(&dealt_body(&self.name, node.index, position, share)));
                node.receive(share, receipt);
            }
        }
        Ok(())
    }
}

pub fn audit_node(
    node: &ComputingNode,
    dealer: &str,
    verifying_key: &VerifyingKey,
    claimed: &[i128],
) -> Vec<usize> {
    claimed
        .iter()
        .enumerate()
        .filter_map(|(position, value)| {
            let signature = node.receipts.get(position).and_then(Option::as_ref)?;
            verifying_key
                .verify(&dealt_body(dealer, node.index, position, *value), signature)
                .is_err()
                .then_some(position)
        })
        .chain((0..claimed.len()).filter(|position| {
            node.receipts
                .get(*position)
                .and_then(Option::as_ref)
                .is_none()
        }))
        .collect()
}
