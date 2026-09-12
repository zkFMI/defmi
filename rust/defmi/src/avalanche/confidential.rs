//! Asset-independent wallet discovery and canonical encrypted claim recovery.
use super::*;
use crate::confidential_notes::AssetIdentity;
use zkfmi_crypto::sealed::{SealedMessage, SealingPurpose};

#[derive(Clone, Debug)]
pub struct CanonicalConfidentialNotePage {
    pub state_root: [u8; 32],
    pub notes: Vec<(NoteOutput, AssetIdentity)>,
    pub next: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct CanonicalConfidentialClaim {
    pub claim: CanonicalNoteClaim,
    pub identity: AssetIdentity,
    pub asset_opening: SealedMessage,
}

impl AvalancheRpcClient {
    pub fn confidential_asset_identity(
        &self,
        commitment: [u8; 32],
    ) -> Result<([u8; 32], AssetIdentity), String> {
        let response = self.call(
            "defmivm.confidentialAssetIdentity",
            json!({"assetCommitment":hex::encode(commitment)}),
        )?;
        let object = result_object(&response)?;
        let identity: AssetIdentity =
            serde_json::from_value(response["identity"].clone()).map_err(|e| e.to_string())?;
        identity.validate()?;
        if identity.commitment != commitment {
            return Err("L1 returned another confidential asset identity".into());
        }
        Ok((result_hex32(object, "stateRoot")?, identity))
    }

    /// This request deliberately contains no asset identifier or commitment.
    pub fn confidential_note_page(
        &self,
        after: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<CanonicalConfidentialNotePage, String> {
        if !(1..=256).contains(&limit) {
            return Err("confidential page limit must be 1..256".into());
        }
        let response = self.call(
            "defmivm.listConfidentialNotes",
            json!({"after":after.map(hex::encode).unwrap_or_default(),"limit":limit}),
        )?;
        let root = result_hex32(result_object(&response)?, "stateRoot")?;
        let values = response["notes"]
            .as_array()
            .ok_or("L1 confidential page lacks notes")?;
        if values.len() > limit {
            return Err("L1 confidential page exceeds its requested limit".into());
        }
        let mut previous = after;
        let mut notes = Vec::with_capacity(values.len());
        for value in values {
            let note = CanonicalNote::parse(&value["note"])?;
            let identity: AssetIdentity =
                serde_json::from_value(value["identity"].clone()).map_err(|e| e.to_string())?;
            identity.validate()?;
            if note.state_root != root
                || note.output.asset_id != identity.commitment
                || previous.is_some_and(|id| note.output.note_id <= id)
            {
                return Err("L1 confidential page mixes roots, identities or cursor order".into());
            }
            previous = Some(note.output.note_id);
            notes.push((note.output, identity));
        }
        let next = match response["next"]
            .as_str()
            .ok_or("L1 confidential page lacks a cursor")?
        {
            "" => None,
            text => Some(
                hex::decode(text)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "invalid confidential cursor length")?,
            ),
        };
        if next.is_some() && (notes.len() != limit || next != previous) {
            return Err("L1 confidential cursor does not follow its page".into());
        }
        Ok(CanonicalConfidentialNotePage {
            state_root: root,
            notes,
            next,
        })
    }

    pub fn confidential_note_claim(
        &self,
        claim_id: [u8; 32],
    ) -> Result<CanonicalConfidentialClaim, String> {
        let response = self.call(
            "defmivm.confidentialNoteClaim",
            json!({"claimID":hex::encode(claim_id)}),
        )?;
        let root = result_hex32(result_object(&response)?, "stateRoot")?;
        let claim = CanonicalNoteClaim::parse(&response["claim"])?;
        let identity: AssetIdentity =
            serde_json::from_value(response["identity"].clone()).map_err(|e| e.to_string())?;
        let asset_opening: SealedMessage =
            serde_json::from_value(response["assetOpening"].clone()).map_err(|e| e.to_string())?;
        identity.validate()?;
        asset_opening
            .validate(SealingPurpose::NoteOpening, 64)
            .map_err(|e| e.to_string())?;
        if claim.claim_id != claim_id
            || claim.state_root != root
            || claim.asset_id != identity.commitment
        {
            return Err("L1 confidential claim has another ID, root or asset identity".into());
        }
        claim.claim()?;
        Ok(CanonicalConfidentialClaim {
            claim,
            identity,
            asset_opening,
        })
    }
}
