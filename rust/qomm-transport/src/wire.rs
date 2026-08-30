//! Constant-size frames and the additive shares that fill them.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAGIC: [u8; 8] = *b"QOMMWIRE";
/// Version 4 carries fourteen fixed field elements. In addition to the ten v3
/// request fields it contains the Taker's two pre-authorized reserve values and
/// blindings. Maker reserves remain resident standing state; Taker reserves are
/// job-specific and therefore must travel with the signed RFQ rather than being
/// frozen into the node's long-lived MPC state.
pub const VERSION: u8 = 4;
pub const PAYLOAD_BYTES: usize = 448;
pub const MAC_BYTES: usize = 32;
pub const HEADER_BYTES: usize = 8 + 1 + 4 + 2;
pub const FRAME_BYTES: usize = HEADER_BYTES + PAYLOAD_BYTES + MAC_BYTES;

/// The Ed25519 scalar-field order used by the pinned MP-SPDZ Shamir build,
/// represented little-endian in four limbs.
///
/// The fixed frames are additive *input* shares: the MPC circuit reads one
/// value from every party and adds them.  Sharing in the Curve25519 base field
/// (`2^255 - 19`) used to reconstruct correctly in this module's tests but
/// produced a different value once MP-SPDZ reduced the sum in its scalar
/// field.  Using the execution field here makes the wire value and the value
/// consumed by `secret_input()` identical, including wraparound.
const FIELD: FieldElement = FieldElement([
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
]);

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct FieldElement(pub [u64; 4]);

impl Ord for FieldElement {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for FieldElement {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement(0x{})", hex::encode(self.to_be_bytes()))
    }
}

impl FieldElement {
    pub const ZERO: Self = Self([0; 4]);

    pub const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }

    pub const fn from_u128(value: u128) -> Self {
        Self([value as u64, (value >> 64) as u64, 0, 0])
    }

    pub fn as_u128(self) -> Option<u128> {
        (self.0[2] == 0 && self.0[3] == 0)
            .then_some(self.0[0] as u128 | ((self.0[1] as u128) << 64))
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, WireError> {
        let mut limbs = [0_u64; 4];
        for (index, chunk) in bytes.rchunks_exact(8).enumerate() {
            limbs[index] = u64::from_be_bytes(chunk.try_into().expect("eight-byte chunk"));
        }
        let value = Self(limbs);
        if value >= FIELD {
            return Err(WireError::FieldElement);
        }
        Ok(value)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (index, limb) in self.0.iter().enumerate() {
            let start = 24 - index * 8;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    fn random(rng: &mut impl RngCore) -> Self {
        loop {
            let mut bytes = [0_u8; 32];
            rng.fill_bytes(&mut bytes);
            // The modulus is just above 2^252.  Masking to 253 bits keeps
            // rejection bounded to roughly two draws without bias.
            bytes[0] &= 0x1f;
            if let Ok(value) = Self::from_be_bytes(bytes) {
                return value;
            }
        }
    }

    pub(crate) fn add_mod(self, other: Self) -> Self {
        let (sum, overflow) = add_raw(self, other);
        debug_assert!(!overflow);
        if sum >= FIELD {
            sub_raw(sum, FIELD).0
        } else {
            sum
        }
    }

    fn sub_mod(self, other: Self) -> Self {
        if self >= other {
            sub_raw(self, other).0
        } else {
            let difference = sub_raw(other, self).0;
            sub_raw(FIELD, difference).0
        }
    }
}

fn add_raw(left: FieldElement, right: FieldElement) -> (FieldElement, bool) {
    let mut out = [0_u64; 4];
    let mut carry = false;
    for (index, output) in out.iter_mut().enumerate() {
        let (first, a) = left.0[index].overflowing_add(right.0[index]);
        let (second, b) = first.overflowing_add(u64::from(carry));
        *output = second;
        carry = a || b;
    }
    (FieldElement(out), carry)
}

fn sub_raw(left: FieldElement, right: FieldElement) -> (FieldElement, bool) {
    let mut out = [0_u64; 4];
    let mut borrow = false;
    for (index, output) in out.iter_mut().enumerate() {
        let (first, a) = left.0[index].overflowing_sub(right.0[index]);
        let (second, b) = first.overflowing_sub(u64::from(borrow));
        *output = second;
        borrow = a || b;
    }
    (FieldElement(out), borrow)
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum WireError {
    #[error("payload must be exactly {PAYLOAD_BYTES} bytes")]
    PayloadSize,
    #[error("frame must be {FRAME_BYTES} bytes, got {0}")]
    FrameSize(usize),
    #[error("bad frame header")]
    Header,
    #[error("node index is outside the unsigned 16-bit range")]
    Node,
    #[error("request does not fit the fixed payload")]
    RequestSize,
    #[error("sharing needs at least two nodes")]
    NodeCount,
    #[error("wire field element is not canonical")]
    FieldElement,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Frame {
    pub slot: u32,
    pub node: u16,
    pub payload: [u8; PAYLOAD_BYTES],
    pub mac: [u8; MAC_BYTES],
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("slot", &self.slot)
            .field("node", &self.node)
            .field("payload_bytes", &PAYLOAD_BYTES)
            .field("mac", &hex::encode(self.mac))
            .finish()
    }
}

impl Frame {
    pub fn new(
        slot: u32,
        node: usize,
        payload: [u8; PAYLOAD_BYTES],
        key: &[u8],
    ) -> Result<Self, WireError> {
        let node = u16::try_from(node).map_err(|_| WireError::Node)?;
        let mac = frame_mac(key, slot, node, &payload);
        Ok(Self {
            slot,
            node,
            payload,
            mac,
        })
    }

    pub fn encode(&self) -> [u8; FRAME_BYTES] {
        let mut out = [0_u8; FRAME_BYTES];
        out[..8].copy_from_slice(&MAGIC);
        out[8] = VERSION;
        out[9..13].copy_from_slice(&self.slot.to_be_bytes());
        out[13..15].copy_from_slice(&self.node.to_be_bytes());
        out[HEADER_BYTES..HEADER_BYTES + PAYLOAD_BYTES].copy_from_slice(&self.payload);
        out[HEADER_BYTES + PAYLOAD_BYTES..].copy_from_slice(&self.mac);
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WireError> {
        if raw.len() != FRAME_BYTES {
            return Err(WireError::FrameSize(raw.len()));
        }
        if raw[..8] != MAGIC || raw[8] != VERSION {
            return Err(WireError::Header);
        }
        let slot = u32::from_be_bytes(raw[9..13].try_into().expect("four-byte slot"));
        let node = u16::from_be_bytes(raw[13..15].try_into().expect("two-byte node"));
        let payload = raw[HEADER_BYTES..HEADER_BYTES + PAYLOAD_BYTES]
            .try_into()
            .expect("fixed payload");
        let mac = raw[HEADER_BYTES + PAYLOAD_BYTES..]
            .try_into()
            .expect("fixed MAC");
        Ok(Self {
            slot,
            node,
            payload,
            mac,
        })
    }
}

pub fn share_request(
    values: &[u128],
    n_nodes: usize,
) -> Result<Vec<[u8; PAYLOAD_BYTES]>, WireError> {
    share_request_with_rng(values, n_nodes, &mut OsRng)
}

pub fn share_request_with_rng(
    values: &[u128],
    n_nodes: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<[u8; PAYLOAD_BYTES]>, WireError> {
    let values = values
        .iter()
        .copied()
        .map(FieldElement::from_u128)
        .collect::<Vec<_>>();
    share_field_elements_with_rng(&values, n_nodes, rng)
}

/// Share canonical execution-field elements without narrowing a Pedersen
/// blinding to `u128`. This is the product path; `share_request` remains the
/// convenient small-integer fixture API.
pub fn share_field_elements(
    values: &[FieldElement],
    n_nodes: usize,
) -> Result<Vec<[u8; PAYLOAD_BYTES]>, WireError> {
    share_field_elements_with_rng(values, n_nodes, &mut OsRng)
}

pub fn share_field_elements_with_rng(
    values: &[FieldElement],
    n_nodes: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<[u8; PAYLOAD_BYTES]>, WireError> {
    if n_nodes < 2 {
        return Err(WireError::NodeCount);
    }
    if values.len() * 32 > PAYLOAD_BYTES {
        return Err(WireError::RequestSize);
    }
    let mut columns = Vec::with_capacity(values.len());
    for value in values {
        let mut shares = Vec::with_capacity(n_nodes);
        let mut sum = FieldElement::ZERO;
        for _ in 0..n_nodes - 1 {
            let share = FieldElement::random(rng);
            sum = sum.add_mod(share);
            shares.push(share);
        }
        shares.push(value.sub_mod(sum));
        columns.push(shares);
    }
    let mut payloads = Vec::with_capacity(n_nodes);
    for node in 0..n_nodes {
        let mut payload = [0_u8; PAYLOAD_BYTES];
        for (index, column) in columns.iter().enumerate() {
            payload[index * 32..(index + 1) * 32].copy_from_slice(&column[node].to_be_bytes());
        }
        rng.fill_bytes(&mut payload[values.len() * 32..]);
        payloads.push(payload);
    }
    Ok(payloads)
}

pub fn reconstruct(
    payloads: &[[u8; PAYLOAD_BYTES]],
    n_values: usize,
) -> Result<Vec<FieldElement>, WireError> {
    if n_values * 32 > PAYLOAD_BYTES {
        return Err(WireError::RequestSize);
    }
    let mut out = Vec::with_capacity(n_values);
    for index in 0..n_values {
        let mut total = FieldElement::ZERO;
        for payload in payloads {
            let bytes = payload[index * 32..(index + 1) * 32]
                .try_into()
                .expect("32-byte field element");
            total = total.add_mod(FieldElement::from_be_bytes(bytes)?);
        }
        out.push(total);
    }
    Ok(out)
}

fn hmac_sha256(key: &[u8], body: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..64 {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(body);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

pub fn frame_mac(key: &[u8], slot: u32, node: u16, payload: &[u8; PAYLOAD_BYTES]) -> [u8; 32] {
    let mut body = Vec::with_capacity(HEADER_BYTES + PAYLOAD_BYTES);
    body.extend_from_slice(&MAGIC);
    body.push(VERSION);
    body.extend_from_slice(&slot.to_be_bytes());
    body.extend_from_slice(&node.to_be_bytes());
    body.extend_from_slice(payload);
    hmac_sha256(key, &body)
}

pub fn frame_is_authentic(key: &[u8], frame: &Frame) -> bool {
    let expected = frame_mac(key, frame.slot, frame.node, &frame.payload);
    expected
        .iter()
        .zip(frame.mac)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
