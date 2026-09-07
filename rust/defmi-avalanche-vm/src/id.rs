use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Id(pub [u8; 32]);

impl Id {
    pub const ZERO: Self = Self([0; 32]);

    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| format!("Avalanche ID must contain 32 bytes, got {}", bytes.len()))
    }

    pub fn to_cb58(self) -> String {
        cb58_encode(&self.0)
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_cb58())
    }
}

impl fmt::Display for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_cb58())
    }
}

impl FromStr for Id {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let decoded = cb58_decode(value)?;
        Self::from_slice(&decoded)
    }
}

pub fn cb58_encode(bytes: &[u8]) -> String {
    let checksum = Sha256::digest(bytes);
    let mut checked = Vec::with_capacity(bytes.len() + 4);
    checked.extend_from_slice(bytes);
    checked.extend_from_slice(&checksum[checksum.len() - 4..]);
    bs58::encode(checked).into_string()
}

pub fn cb58_decode(value: &str) -> Result<Vec<u8>, String> {
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|error| format!("invalid CB58 value: {error}"))?;
    if decoded.len() < 4 {
        return Err("CB58 value has no checksum".into());
    }
    let split = decoded.len() - 4;
    let (raw, checksum) = decoded.split_at(split);
    let expected = Sha256::digest(raw);
    if checksum != &expected[expected.len() - 4..] {
        return Err("CB58 checksum mismatch".into());
    }
    Ok(raw.to_vec())
}

pub fn vm_id() -> Id {
    let mut raw = [0u8; 32];
    raw[..7].copy_from_slice(b"defmivm");
    Id(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cb58_round_trip_and_checksum_rejection() {
        let raw = [42u8; 32];
        let encoded = cb58_encode(&raw);
        assert_eq!(cb58_decode(&encoded).expect("decode"), raw);
        let mut damaged = encoded.into_bytes();
        let last = damaged.len() - 1;
        damaged[last] = if damaged[last] == b'1' { b'2' } else { b'1' };
        assert!(cb58_decode(std::str::from_utf8(&damaged).expect("ASCII")).is_err());
    }

    #[test]
    fn vm_id_is_stable() {
        assert_eq!(&vm_id().0[..7], b"defmivm");
        assert_eq!(vm_id().to_string().parse::<Id>().expect("parse"), vm_id());
    }
}
