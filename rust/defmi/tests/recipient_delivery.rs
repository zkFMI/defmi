//! Stored delivery remains decryptable after recovery of all independent keys.
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use defmi::{
    note_chain::NoteOutput,
    notes::{NoteLedger, NoteOpening, Wallet},
};
use zkfmi_zk::pedersen::Pedersen;
use rand::rngs::OsRng;
use zkfmi_crypto::{hybrid::kem::HybridKemKey, sealed::SealingPurpose};

#[test]
fn canonical_delivery_roundtrip_requires_the_independent_recipient_key() {
    let view = Scalar::from(71u64);
    let spend = Scalar::from(72u64);
    let recipient_seed = [73u8; 96];
    let wallet = Wallet::from_parts(view, spend, HybridKemKey::from_seed(&recipient_seed));
    let key = Pedersen::new(b"recipient-delivery-test");
    let mut ledger = NoteLedger::new(key.clone(), 32);
    let blinding = Scalar::from(74u64);
    let note = ledger
        .build_note(
            &wallet.address,
            123,
            key.commit_u64(123, &blinding),
            &blinding,
            &mut OsRng,
        )
        .unwrap();
    let output = NoteOutput::from_note(&note, [75; 32], [0; 32]).unwrap();
    let encoded = serde_json::to_vec(&output.body().unwrap()).unwrap();
    drop(wallet);
    let restored = Wallet::from_parts(view, spend, HybridKemKey::from_seed(&recipient_seed));
    let decoded = NoteOutput::from_body(&serde_json::from_slice(&encoded).unwrap()).unwrap();
    assert_eq!(decoded, output);
    ledger.add(note.clone());
    let recovered = ledger.scan(&restored, &key);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].1.value, 123);
    assert_eq!(recovered[0].1.blinding, blinding);
    // Even recovery of BOTH classical wallet secrets cannot open the payload.
    let classical_only = Wallet::from_parts(view, spend, HybridKemKey::generate().unwrap());
    assert!(ledger.scan(&classical_only, &key).is_empty());
    let original = ledger.commitment_of(&note);
    let mut variants = Vec::new();
    for index in 0..7 {
        let mut changed = note.clone();
        let NoteOpening::Recipient(ref mut envelope) = changed.encrypted_opening else {
            unreachable!()
        };
        match index {
            0 => envelope.kem_ciphertext[0] ^= 8,
            1 => envelope.kem_ciphertext[32] ^= 1,
            2 => envelope.nonce[0] ^= 1,
            3 => envelope.ciphertext[0] ^= 1,
            4 => envelope.tag[0] ^= 1,
            5 => envelope.purpose = SealingPurpose::CredentialCustody,
            _ => changed.value_commitment += G,
        }
        variants.push(changed);
    }
    for changed in variants {
        assert_ne!(ledger.commitment_of(&changed), original);
        ledger.notes[0] = changed;
        assert!(ledger.scan(&restored, &key).is_empty());
    }
    let mut legacy = output.body().unwrap();
    legacy.as_object_mut().unwrap().remove("encrypted_opening");
    legacy["masked_value"] = serde_json::json!("00".repeat(32));
    legacy["masked_blinding"] = serde_json::json!("00".repeat(32));
    assert!(NoteOutput::from_body(&legacy).is_err());
}
