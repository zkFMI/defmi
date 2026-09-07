//! Consensus-safe, resumable state summaries for the QOMM RPCChainVM.
//!
//! Avalanche's state-summary frontier is gossiped as one network message, so a
//! summary must not contain the whole DeFMI ledger. QOMM commits to a bounded
//! canonical snapshot here and transfers it through application messages in
//! independently verifiable chunks. A joining validator installs nothing
//! until every chunk, the Merkle root, the whole-snapshot digest, the block ID,
//! and the canonical state root agree.

use sha2::{Digest, Sha256};

use crate::{block::Block, id::Id, state::State};

const SUMMARY_MAGIC: &[u8; 8] = b"QOMMSSM1";
const SNAPSHOT_MAGIC: &[u8; 8] = b"QOMMSNP1";
const REQUEST_MAGIC: &[u8; 8] = b"QOMMSSR1";
const RESPONSE_MAGIC: &[u8; 8] = b"QOMMSSD1";
const SUMMARY_VERSION: u16 = 1;
const LEAF_DOMAIN: &[u8] = b"QOMM:STATE-SYNC:LEAF:v1";
const NODE_DOMAIN: &[u8] = b"QOMM:STATE-SYNC:NODE:v1";
const SNAPSHOT_DOMAIN: &[u8] = b"QOMM:STATE-SYNC:SNAPSHOT:v1";

/// Small enough to remain below Avalanche application-message limits while
/// large enough to avoid excessive request overhead on WAN deployments.
pub const CHUNK_BYTES: usize = 512 * 1024;
pub const MAX_SNAPSHOT_BYTES: usize = 66 * 1024 * 1024;
pub const MAX_MERKLE_DEPTH: usize = 32;

const SUMMARY_BYTES: usize = 8 + 2 + 4 + 7 * 32 + 8 + 8 + 8 + 4 + 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSummary {
    pub network_id: u32,
    pub chain_id: Id,
    pub genesis_hash: Id,
    pub block_id: Id,
    pub parent_id: Id,
    pub state_root: [u8; 32],
    pub snapshot_hash: [u8; 32],
    pub chunk_root: [u8; 32],
    pub height: u64,
    pub timestamp: i64,
    pub snapshot_len: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
}

impl StateSummary {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = Vec::with_capacity(SUMMARY_BYTES);
        out.extend_from_slice(SUMMARY_MAGIC);
        out.extend_from_slice(&SUMMARY_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id.to_be_bytes());
        for value in [
            self.chain_id.0,
            self.genesis_hash.0,
            self.block_id.0,
            self.parent_id.0,
            self.state_root,
            self.snapshot_hash,
            self.chunk_root,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.snapshot_len.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        debug_assert_eq!(out.len(), SUMMARY_BYTES);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != SUMMARY_BYTES {
            return Err(format!(
                "state summary has {} bytes; expected {SUMMARY_BYTES}",
                bytes.len()
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != SUMMARY_MAGIC {
            return Err("state summary magic is unsupported".into());
        }
        if reader.u16()? != SUMMARY_VERSION {
            return Err("state summary version is unsupported".into());
        }
        let summary = Self {
            network_id: reader.u32()?,
            chain_id: Id(reader.array()?),
            genesis_hash: Id(reader.array()?),
            block_id: Id(reader.array()?),
            parent_id: Id(reader.array()?),
            state_root: reader.array()?,
            snapshot_hash: reader.array()?,
            chunk_root: reader.array()?,
            height: reader.u64()?,
            timestamp: reader.i64()?,
            snapshot_len: reader.u64()?,
            chunk_size: reader.u32()?,
            chunk_count: reader.u32()?,
        };
        if !reader.is_empty() {
            return Err("state summary has trailing bytes".into());
        }
        summary.validate()?;
        if summary.encode()? != bytes {
            return Err("state summary encoding is not canonical".into());
        }
        Ok(summary)
    }

    pub fn id(&self) -> Result<Id, String> {
        self.encode().map(|bytes| Id::digest(&bytes))
    }

    pub fn validate(&self) -> Result<(), String> {
        let snapshot_len = usize::try_from(self.snapshot_len)
            .map_err(|_| "state snapshot length exceeds this platform".to_string())?;
        if self.chain_id == Id::ZERO
            || self.genesis_hash == Id::ZERO
            || self.block_id == Id::ZERO
            || self.state_root == [0; 32]
            || self.snapshot_hash == [0; 32]
            || self.chunk_root == [0; 32]
            || self.timestamp < 0
            || snapshot_len == 0
            || snapshot_len > MAX_SNAPSHOT_BYTES
            || usize::try_from(self.chunk_size).ok() != Some(CHUNK_BYTES)
        {
            return Err("state summary contains an invalid fixed field".into());
        }
        let expected = snapshot_len.div_ceil(CHUNK_BYTES);
        if expected == 0 || usize::try_from(self.chunk_count).ok() != Some(expected) {
            return Err("state summary chunk count does not match its snapshot length".into());
        }
        Ok(())
    }

    pub fn matches_chain(&self, network_id: u32, chain_id: Id, genesis_hash: Id) -> bool {
        self.network_id == network_id
            && self.chain_id == chain_id
            && self.genesis_hash == genesis_hash
    }
}

#[derive(Debug)]
pub struct DecodedSnapshot {
    pub block: Block,
    pub block_bytes: Vec<u8>,
    pub state: State,
}

pub fn build_summary(
    network_id: u32,
    chain_id: Id,
    genesis_hash: Id,
    block: &Block,
    state: &State,
) -> Result<(StateSummary, Vec<u8>), String> {
    let block_bytes = block.encode()?;
    let state_bytes = state.encode()?;
    let block_len = u32::try_from(block_bytes.len())
        .map_err(|_| "state snapshot block is too large".to_string())?;
    let state_len = u64::try_from(state_bytes.len())
        .map_err(|_| "state snapshot state is too large".to_string())?;
    let mut snapshot =
        Vec::with_capacity(SNAPSHOT_MAGIC.len() + 4 + 8 + block_bytes.len() + state_bytes.len());
    snapshot.extend_from_slice(SNAPSHOT_MAGIC);
    snapshot.extend_from_slice(&block_len.to_be_bytes());
    snapshot.extend_from_slice(&state_len.to_be_bytes());
    snapshot.extend_from_slice(&block_bytes);
    snapshot.extend_from_slice(&state_bytes);
    if snapshot.len() > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "state snapshot has {} bytes; maximum is {MAX_SNAPSHOT_BYTES}",
            snapshot.len()
        ));
    }
    let chunks = snapshot.chunks(CHUNK_BYTES).collect::<Vec<_>>();
    let chunk_count = u32::try_from(chunks.len())
        .map_err(|_| "state snapshot has too many chunks".to_string())?;
    let snapshot_len = u64::try_from(snapshot.len())
        .map_err(|_| "state snapshot length exceeds u64".to_string())?;
    let summary = StateSummary {
        network_id,
        chain_id,
        genesis_hash,
        block_id: block.id()?,
        parent_id: block.parent_id,
        state_root: state.root(),
        snapshot_hash: snapshot_digest(&snapshot),
        chunk_root: merkle_root(&chunks)?,
        height: block.height,
        timestamp: block.timestamp,
        snapshot_len,
        chunk_size: CHUNK_BYTES as u32,
        chunk_count,
    };
    summary.validate()?;
    Ok((summary, snapshot))
}

pub fn decode_snapshot(summary: &StateSummary, snapshot: &[u8]) -> Result<DecodedSnapshot, String> {
    summary.validate()?;
    if usize::try_from(summary.snapshot_len).ok() != Some(snapshot.len())
        || snapshot_digest(snapshot) != summary.snapshot_hash
    {
        return Err("state snapshot length or digest differs from its summary".into());
    }
    let chunks = snapshot.chunks(CHUNK_BYTES).collect::<Vec<_>>();
    if merkle_root(&chunks)? != summary.chunk_root {
        return Err("state snapshot chunks differ from their Merkle root".into());
    }
    let mut reader = Reader::new(snapshot);
    if reader.take(8)? != SNAPSHOT_MAGIC {
        return Err("state snapshot magic is unsupported".into());
    }
    let block_len = usize::try_from(reader.u32()?)
        .map_err(|_| "state snapshot block length exceeds this platform".to_string())?;
    let state_len = usize::try_from(reader.u64()?)
        .map_err(|_| "state snapshot state length exceeds this platform".to_string())?;
    let block_bytes = reader.take(block_len)?.to_vec();
    let state_bytes = reader.take(state_len)?;
    if !reader.is_empty() {
        return Err("state snapshot has trailing bytes".into());
    }
    let block = Block::decode(&block_bytes)?;
    let state = State::decode(state_bytes)?;
    if block.id()? != summary.block_id
        || block.parent_id != summary.parent_id
        || block.height != summary.height
        || block.timestamp != summary.timestamp
        || state.root() != summary.state_root
    {
        return Err("state snapshot block or state differs from its summary".into());
    }
    Ok(DecodedSnapshot {
        block,
        block_bytes,
        state,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkRequest {
    pub summary: StateSummary,
    pub index: u32,
}

impl ChunkRequest {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.index >= self.summary.chunk_count {
            return Err("state chunk request index is outside the summary".into());
        }
        let summary = self.summary.encode()?;
        let mut out = Vec::with_capacity(8 + summary.len() + 4);
        out.extend_from_slice(REQUEST_MAGIC);
        out.extend_from_slice(&summary);
        out.extend_from_slice(&self.index.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 8 + SUMMARY_BYTES + 4 || &bytes[..8] != REQUEST_MAGIC {
            return Err("state chunk request has an unsupported envelope".into());
        }
        let summary = StateSummary::decode(&bytes[8..8 + SUMMARY_BYTES])?;
        let index = u32::from_be_bytes(
            bytes[8 + SUMMARY_BYTES..]
                .try_into()
                .map_err(|_| "state chunk request is truncated".to_string())?,
        );
        if index >= summary.chunk_count {
            return Err("state chunk request index is outside the summary".into());
        }
        Ok(Self { summary, index })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkResponse {
    pub summary_id: Id,
    pub index: u32,
    pub chunk_count: u32,
    pub proof: Vec<[u8; 32]>,
    pub bytes: Vec<u8>,
}

impl ChunkResponse {
    pub fn build(summary: &StateSummary, snapshot: &[u8], index: u32) -> Result<Self, String> {
        decode_snapshot(summary, snapshot)?;
        if index >= summary.chunk_count {
            return Err("state chunk response index is outside the summary".into());
        }
        let chunks = snapshot.chunks(CHUNK_BYTES).collect::<Vec<_>>();
        Ok(Self {
            summary_id: summary.id()?,
            index,
            chunk_count: summary.chunk_count,
            proof: merkle_proof(&chunks, index as usize)?,
            bytes: chunks[index as usize].to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.summary_id == Id::ZERO
            || self.chunk_count == 0
            || self.index >= self.chunk_count
            || self.proof.len() > MAX_MERKLE_DEPTH
            || self.bytes.is_empty()
            || self.bytes.len() > CHUNK_BYTES
        {
            return Err("state chunk response contains invalid dimensions".into());
        }
        let proof_len = u16::try_from(self.proof.len())
            .map_err(|_| "state chunk proof is too deep".to_string())?;
        let byte_len =
            u32::try_from(self.bytes.len()).map_err(|_| "state chunk is too large".to_string())?;
        let mut out =
            Vec::with_capacity(8 + 32 + 4 + 4 + 2 + self.proof.len() * 32 + 4 + self.bytes.len());
        out.extend_from_slice(RESPONSE_MAGIC);
        out.extend_from_slice(&self.summary_id.0);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&proof_len.to_be_bytes());
        for sibling in &self.proof {
            out.extend_from_slice(sibling);
        }
        out.extend_from_slice(&byte_len.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != RESPONSE_MAGIC {
            return Err("state chunk response magic is unsupported".into());
        }
        let summary_id = Id(reader.array()?);
        let index = reader.u32()?;
        let chunk_count = reader.u32()?;
        let proof_len = usize::from(reader.u16()?);
        if proof_len > MAX_MERKLE_DEPTH {
            return Err("state chunk proof is too deep".into());
        }
        let proof = (0..proof_len)
            .map(|_| reader.array())
            .collect::<Result<Vec<_>, _>>()?;
        let byte_len = usize::try_from(reader.u32()?)
            .map_err(|_| "state chunk length exceeds this platform".to_string())?;
        if byte_len == 0 || byte_len > CHUNK_BYTES {
            return Err("state chunk length is outside its bound".into());
        }
        let chunk = reader.take(byte_len)?.to_vec();
        if !reader.is_empty() {
            return Err("state chunk response has trailing bytes".into());
        }
        let response = Self {
            summary_id,
            index,
            chunk_count,
            proof,
            bytes: chunk,
        };
        response.encode()?;
        Ok(response)
    }

    pub fn verify(&self, summary: &StateSummary) -> Result<(), String> {
        if self.summary_id != summary.id()?
            || self.chunk_count != summary.chunk_count
            || self.index >= self.chunk_count
        {
            return Err("state chunk response names another summary or index".into());
        }
        let expected_len = if self.index + 1 == self.chunk_count {
            let prefix = usize::try_from(self.index)
                .map_err(|_| "state chunk index exceeds this platform".to_string())?
                .checked_mul(CHUNK_BYTES)
                .ok_or_else(|| "state chunk offset overflow".to_string())?;
            usize::try_from(summary.snapshot_len)
                .map_err(|_| "state snapshot length exceeds this platform".to_string())?
                .checked_sub(prefix)
                .ok_or_else(|| "state chunk offset exceeds the snapshot".to_string())?
        } else {
            CHUNK_BYTES
        };
        if self.bytes.len() != expected_len
            || !verify_merkle_proof(
                &self.bytes,
                self.index as usize,
                self.chunk_count as usize,
                &self.proof,
                summary.chunk_root,
            )
        {
            return Err("state chunk data or Merkle proof is invalid".into());
        }
        Ok(())
    }
}

fn snapshot_digest(snapshot: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(SNAPSHOT_DOMAIN)
        .chain_update((snapshot.len() as u64).to_be_bytes())
        .chain_update(snapshot)
        .finalize()
        .into()
}

fn leaf_hash(index: usize, bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(LEAF_DOMAIN)
        .chain_update((index as u64).to_be_bytes())
        .chain_update((bytes.len() as u64).to_be_bytes())
        .chain_update(bytes)
        .finalize()
        .into()
}

fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(NODE_DOMAIN)
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

fn merkle_leaves(chunks: &[&[u8]]) -> Result<Vec<[u8; 32]>, String> {
    if chunks.is_empty() || chunks.len() > u32::MAX as usize {
        return Err("state snapshot chunk count is outside its bound".into());
    }
    Ok(chunks
        .iter()
        .enumerate()
        .map(|(index, bytes)| leaf_hash(index, bytes))
        .collect())
}

fn merkle_root(chunks: &[&[u8]]) -> Result<[u8; 32], String> {
    let mut level = merkle_leaves(chunks)?;
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| node_hash(pair[0], *pair.get(1).unwrap_or(&pair[0])))
            .collect();
    }
    Ok(level[0])
}

fn merkle_proof(chunks: &[&[u8]], index: usize) -> Result<Vec<[u8; 32]>, String> {
    if index >= chunks.len() {
        return Err("state chunk proof index is outside the snapshot".into());
    }
    let mut level = merkle_leaves(chunks)?;
    let mut position = index;
    let mut proof = Vec::new();
    while level.len() > 1 {
        let sibling = if position.is_multiple_of(2) {
            *level.get(position + 1).unwrap_or(&level[position])
        } else {
            level[position - 1]
        };
        proof.push(sibling);
        level = level
            .chunks(2)
            .map(|pair| node_hash(pair[0], *pair.get(1).unwrap_or(&pair[0])))
            .collect();
        position /= 2;
    }
    if proof.len() > MAX_MERKLE_DEPTH {
        return Err("state chunk proof exceeds the supported depth".into());
    }
    Ok(proof)
}

fn verify_merkle_proof(
    bytes: &[u8],
    index: usize,
    count: usize,
    proof: &[[u8; 32]],
    expected_root: [u8; 32],
) -> bool {
    if count == 0 || index >= count {
        return false;
    }
    let expected_depth = usize::BITS as usize - (count.saturating_sub(1)).leading_zeros() as usize;
    if proof.len() != expected_depth {
        return false;
    }
    let mut hash = leaf_hash(index, bytes);
    let mut position = index;
    let mut width = count;
    for sibling in proof {
        hash = if position.is_multiple_of(2) {
            node_hash(hash, *sibling)
        } else {
            node_hash(*sibling, hash)
        };
        position /= 2;
        width = width.div_ceil(2);
    }
    width == 1 && hash == expected_root
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "state-sync message is truncated".to_string())?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "state-sync message is truncated".to_string())
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (StateSummary, Vec<u8>) {
        let block = Block {
            parent_id: Id([3; 32]),
            timestamp: 100,
            height: 8,
            transactions: Vec::new(),
        };
        build_summary(7, Id([1; 32]), Id([2; 32]), &block, &State::default()).expect("summary")
    }

    #[test]
    fn summary_and_snapshot_round_trip_are_canonical() {
        let (summary, snapshot) = fixture();
        assert_eq!(
            StateSummary::decode(&summary.encode().unwrap()).unwrap(),
            summary
        );
        let decoded = decode_snapshot(&summary, &snapshot).expect("snapshot");
        assert_eq!(decoded.block.height, 8);
        assert_eq!(decoded.state, State::default());
        assert!(summary.matches_chain(7, Id([1; 32]), Id([2; 32])));
        assert!(!summary.matches_chain(8, Id([1; 32]), Id([2; 32])));
    }

    #[test]
    fn snapshot_tampering_is_rejected() {
        let (summary, mut snapshot) = fixture();
        *snapshot.last_mut().expect("nonempty") ^= 1;
        assert!(decode_snapshot(&summary, &snapshot).is_err());
    }

    #[test]
    fn merkle_chunks_verify_independently() {
        let bytes = vec![42u8; CHUNK_BYTES * 2 + 17];
        let chunks = bytes.chunks(CHUNK_BYTES).collect::<Vec<_>>();
        let root = merkle_root(&chunks).expect("root");
        for (index, chunk) in chunks.iter().enumerate() {
            let proof = merkle_proof(&chunks, index).expect("proof");
            assert!(verify_merkle_proof(
                chunk,
                index,
                chunks.len(),
                &proof,
                root
            ));
            let mut damaged = chunk.to_vec();
            damaged[0] ^= 1;
            assert!(!verify_merkle_proof(
                &damaged,
                index,
                chunks.len(),
                &proof,
                root
            ));
        }
    }

    #[test]
    fn chunk_request_and_response_reject_trailing_or_wrong_data() {
        let (summary, snapshot) = fixture();
        let request = ChunkRequest {
            summary: summary.clone(),
            index: 0,
        };
        assert_eq!(
            ChunkRequest::decode(&request.encode().unwrap()).unwrap(),
            request
        );
        let response = ChunkResponse::build(&summary, &snapshot, 0).expect("response");
        let encoded = response.encode().expect("encode response");
        let decoded = ChunkResponse::decode(&encoded).expect("decode response");
        decoded.verify(&summary).expect("verify response");
        let mut trailing = encoded;
        trailing.push(0);
        assert!(ChunkResponse::decode(&trailing).is_err());
        let mut wrong = decoded;
        wrong.bytes[0] ^= 1;
        assert!(wrong.verify(&summary).is_err());
    }
}
