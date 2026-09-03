use crate::id::Id;

const MAGIC: &[u8; 8] = b"QOMMBLK1";
pub const MAX_TRANSACTIONS: usize = 32;
pub const MAX_TRANSACTION_BYTES: usize = 1 << 20;
pub const MAX_BLOCK_BYTES: usize = 3 << 19;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub parent_id: Id,
    pub timestamp: i64,
    pub height: u64,
    pub transactions: Vec<Vec<u8>>,
}

impl Block {
    pub fn validate(&self) -> Result<(), String> {
        if self.timestamp < 0 {
            return Err("block timestamp cannot be negative".into());
        }
        if self.transactions.len() > MAX_TRANSACTIONS {
            return Err(format!(
                "block has {} transactions; maximum is {MAX_TRANSACTIONS}",
                self.transactions.len()
            ));
        }
        if self
            .transactions
            .iter()
            .any(|transaction| transaction.is_empty() || transaction.len() > MAX_TRANSACTION_BYTES)
        {
            return Err("block contains an empty or oversized transaction".into());
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&self.parent_id.0);
        encoded.extend_from_slice(&self.timestamp.to_be_bytes());
        encoded.extend_from_slice(&self.height.to_be_bytes());
        encoded.extend_from_slice(&(self.transactions.len() as u16).to_be_bytes());
        for transaction in &self.transactions {
            encoded.extend_from_slice(&(transaction.len() as u32).to_be_bytes());
            encoded.extend_from_slice(transaction);
        }
        if encoded.len() > MAX_BLOCK_BYTES {
            return Err(format!(
                "block has {} bytes; maximum is {MAX_BLOCK_BYTES}",
                encoded.len()
            ));
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.is_empty() || encoded.len() > MAX_BLOCK_BYTES {
            return Err("block size is outside the allowed range".into());
        }
        let mut offset = 0usize;
        let mut take = |length: usize| -> Result<&[u8], String> {
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= encoded.len())
                .ok_or_else(|| "block is truncated".to_string())?;
            let value = &encoded[offset..end];
            offset = end;
            Ok(value)
        };
        if take(8)? != MAGIC {
            return Err("block magic or version is unsupported".into());
        }
        let parent_id = Id(take(32)?.try_into().map_err(|_| "block is truncated")?);
        let timestamp = i64::from_be_bytes(take(8)?.try_into().map_err(|_| "block is truncated")?);
        let height = u64::from_be_bytes(take(8)?.try_into().map_err(|_| "block is truncated")?);
        let count = usize::from(u16::from_be_bytes(
            take(2)?.try_into().map_err(|_| "block is truncated")?,
        ));
        if count > MAX_TRANSACTIONS {
            return Err("block transaction count exceeds the limit".into());
        }
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let length =
                u32::from_be_bytes(take(4)?.try_into().map_err(|_| "block is truncated")?) as usize;
            if length == 0 || length > MAX_TRANSACTION_BYTES {
                return Err("block transaction size is outside the allowed range".into());
            }
            transactions.push(take(length)?.to_vec());
        }
        if offset != encoded.len() {
            return Err("block contains trailing bytes".into());
        }
        let block = Self {
            parent_id,
            timestamp,
            height,
            transactions,
        };
        block.validate()?;
        Ok(block)
    }

    pub fn id(&self) -> Result<Id, String> {
        self.encode().map(|bytes| Id::digest(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_round_trip_and_id_are_canonical() {
        let block = Block {
            parent_id: Id([7; 32]),
            timestamp: 1,
            height: 2,
            transactions: vec![br#"{"method":"test"}"#.to_vec()],
        };
        let bytes = block.encode().expect("encode");
        assert_eq!(Block::decode(&bytes).expect("decode"), block);
        assert_eq!(block.id().expect("ID"), Id::digest(&bytes));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = Block {
            parent_id: Id::ZERO,
            timestamp: 0,
            height: 0,
            transactions: vec![],
        }
        .encode()
        .expect("encode");
        bytes.push(0);
        assert!(Block::decode(&bytes).is_err());
    }
}
