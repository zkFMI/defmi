//! Anonymous, winner-only delivery of a fixed-size settlement instruction.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::symm::{Cipher, Crypter, Mode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub const DOMAIN: &[u8] = b"QOMM:WINNER:ENVELOPE:v1";
const INNER_DOMAIN: &[u8] = b"QOMM:WINNER:PAYLOAD:v1";
pub const CLEAR_BYTES: usize = 1024;
pub const VERSION: u8 = 1;

#[derive(Clone)]
pub struct X25519PrivateKey(PKey<Private>);

#[derive(Clone)]
pub struct X25519PublicKey(PKey<Public>);

impl X25519PrivateKey {
    pub fn generate() -> Result<Self, String> {
        PKey::generate_x25519()
            .map(Self)
            .map_err(|error| error.to_string())
    }

    pub fn public_key(&self) -> Result<X25519PublicKey, String> {
        let raw = self.0.raw_public_key().map_err(|error| error.to_string())?;
        PKey::public_key_from_raw_bytes(&raw, Id::X25519)
            .map(X25519PublicKey)
            .map_err(|error| error.to_string())
    }

    pub fn raw_private_key(&self) -> Result<[u8; 32], String> {
        self.0
            .raw_private_key()
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "X25519 private key is not 32 bytes".to_string())
    }

    pub fn from_raw(raw: &[u8; 32]) -> Result<Self, String> {
        PKey::private_key_from_raw_bytes(raw, Id::X25519)
            .map(Self)
            .map_err(|error| error.to_string())
    }
}

impl X25519PublicKey {
    pub fn raw_public_key(&self) -> Result<[u8; 32], String> {
        self.0
            .raw_public_key()
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "X25519 public key is not 32 bytes".to_string())
    }

    pub fn from_raw(raw: &[u8; 32]) -> Result<Self, String> {
        PKey::public_key_from_raw_bytes(raw, Id::X25519)
            .map(Self)
            .map_err(|error| error.to_string())
    }
}

pub(crate) fn shared(
    private: &X25519PrivateKey,
    public: &X25519PublicKey,
) -> Result<Vec<u8>, String> {
    let mut deriver = Deriver::new(&private.0).map_err(|error| error.to_string())?;
    deriver
        .set_peer(&public.0)
        .map_err(|error| error.to_string())?;
    deriver.derive_to_vec().map_err(|error| error.to_string())
}

fn hmac_sha256(key: &[u8], body: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
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
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(body)
        .finalize();
    Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

fn derive_key(
    shared: &[u8],
    ephemeral: &[u8; 32],
    context_digest: &[u8; 32],
    quote_digest: &[u8; 32],
) -> [u8; 32] {
    let pseudorandom = hmac_sha256(context_digest, shared);
    let mut info = Vec::with_capacity(DOMAIN.len() + 65);
    info.extend_from_slice(DOMAIN);
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(quote_digest);
    info.push(1);
    hmac_sha256(&pseudorandom, &info)
}

pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    clear: &[u8],
    associated: &[u8],
) -> Result<Vec<u8>, String> {
    let mut crypter = Crypter::new(Cipher::chacha20_poly1305(), Mode::Encrypt, key, Some(nonce))
        .map_err(|error| error.to_string())?;
    crypter
        .aad_update(associated)
        .map_err(|error| error.to_string())?;
    let mut output = vec![0_u8; clear.len() + Cipher::chacha20_poly1305().block_size()];
    let mut written = crypter
        .update(clear, &mut output)
        .map_err(|error| error.to_string())?;
    written += crypter
        .finalize(&mut output[written..])
        .map_err(|error| error.to_string())?;
    output.truncate(written);
    let mut tag = [0_u8; 16];
    crypter
        .get_tag(&mut tag)
        .map_err(|error| error.to_string())?;
    output.extend_from_slice(&tag);
    Ok(output)
}

pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    encrypted: &[u8],
    associated: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    if encrypted.len() < 16 {
        return Err("winner ciphertext is truncated".into());
    }
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
    let mut crypter = Crypter::new(Cipher::chacha20_poly1305(), Mode::Decrypt, key, Some(nonce))
        .map_err(|error| error.to_string())?;
    crypter
        .aad_update(associated)
        .map_err(|error| error.to_string())?;
    crypter.set_tag(tag).map_err(|error| error.to_string())?;
    let mut output = vec![0_u8; ciphertext.len() + Cipher::chacha20_poly1305().block_size()];
    let written = crypter
        .update(ciphertext, &mut output)
        .map_err(|error| error.to_string())?;
    match crypter.finalize(&mut output[written..]) {
        Ok(final_bytes) => {
            output.truncate(written + final_bytes);
            Ok(Some(output))
        }
        Err(_) => Ok(None),
    }
}

#[derive(Clone, Debug)]
pub struct WinnerEnvelope {
    pub version: u8,
    pub ephemeral_public: [u8; 32],
    pub nonce: [u8; 12],
    pub context_digest: [u8; 32],
    pub quote_digest: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub taker_public: [u8; 32],
    pub signature: Signature,
}

impl WinnerEnvelope {
    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if self.version != VERSION {
            return Err("unsupported winner-envelope version".into());
        }
        if self.ciphertext.len() != CLEAR_BYTES + 16 {
            return Err("winner ciphertext is not the fixed wire size".into());
        }
        let mut body = Vec::with_capacity(DOMAIN.len() + 141 + self.ciphertext.len());
        body.extend_from_slice(DOMAIN);
        body.push(self.version);
        body.extend_from_slice(&self.ephemeral_public);
        body.extend_from_slice(&self.nonce);
        body.extend_from_slice(&self.context_digest);
        body.extend_from_slice(&self.quote_digest);
        body.extend_from_slice(&self.taker_public);
        body.extend_from_slice(&self.ciphertext);
        Ok(body)
    }

    pub fn commitment(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::new()
            .chain_update(self.unsigned()?)
            .chain_update(self.signature.to_bytes())
            .finalize()
            .into())
    }

    pub fn verify_taker(&self, expected: Option<&VerifyingKey>) -> bool {
        if expected.is_some_and(|key| key.as_bytes() != &self.taker_public) {
            return false;
        }
        VerifyingKey::from_bytes(&self.taker_public)
            .ok()
            .zip(self.unsigned().ok())
            .is_some_and(|(key, body)| key.verify(&body, &self.signature).is_ok())
    }
}

pub fn seal_for_winner(
    maker_id: &str,
    maker_key: &X25519PublicKey,
    payload: &[u8],
    context: &[u8],
    quote_digest: [u8; 32],
    taker_key: &SigningKey,
) -> Result<WinnerEnvelope, String> {
    let maker = maker_id.as_bytes();
    if maker.is_empty() || maker.len() > 255 {
        return Err("maker identifier must contain 1..255 UTF-8 bytes".into());
    }
    let context_digest: [u8; 32] = Sha256::digest(context).into();
    let mut fixed = Vec::new();
    fixed.extend_from_slice(INNER_DOMAIN);
    fixed.push(maker.len() as u8);
    fixed.extend_from_slice(maker);
    fixed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    fixed.extend_from_slice(payload);
    fixed.extend_from_slice(&context_digest);
    fixed.extend_from_slice(&quote_digest);
    if fixed.len() > CLEAR_BYTES {
        return Err(format!(
            "settlement payload exceeds {CLEAR_BYTES} encrypted bytes"
        ));
    }
    fixed.resize(CLEAR_BYTES, 0);
    OsRng.fill_bytes(&mut fixed[INNER_DOMAIN.len() + 1 + maker.len() + 4 + payload.len() + 64..]);
    let ephemeral_private = X25519PrivateKey::generate()?;
    let ephemeral_public = ephemeral_private.public_key()?.raw_public_key()?;
    let key = derive_key(
        &shared(&ephemeral_private, maker_key)?,
        &ephemeral_public,
        &context_digest,
        &quote_digest,
    );
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let associated = [DOMAIN, &ephemeral_public, &context_digest, &quote_digest].concat();
    let ciphertext = encrypt(&key, &nonce, &fixed, &associated)?;
    let taker_public = taker_key.verifying_key().to_bytes();
    let mut envelope = WinnerEnvelope {
        version: VERSION,
        ephemeral_public,
        nonce,
        context_digest,
        quote_digest,
        ciphertext,
        taker_public,
        signature: Signature::from_bytes(&[0; 64]),
    };
    envelope.signature = taker_key.sign(&envelope.unsigned()?);
    Ok(envelope)
}

pub fn open_if_winner(
    envelope: &WinnerEnvelope,
    maker_id: &str,
    private_keys: &[X25519PrivateKey],
    context: &[u8],
    quote_digest: [u8; 32],
    expected_taker: Option<&VerifyingKey>,
) -> Result<Option<Vec<u8>>, String> {
    if !envelope.verify_taker(expected_taker) {
        return Err("the taker signature on the winner envelope is invalid".into());
    }
    let context_digest: [u8; 32] = Sha256::digest(context).into();
    if envelope.context_digest != context_digest || envelope.quote_digest != quote_digest {
        return Err("the envelope is bound to another quote or market context".into());
    }
    let ephemeral = X25519PublicKey::from_raw(&envelope.ephemeral_public)?;
    let associated = [
        DOMAIN,
        &envelope.ephemeral_public,
        &context_digest,
        &quote_digest,
    ]
    .concat();
    let mut clear = None;
    for private in private_keys {
        let key = derive_key(
            &shared(private, &ephemeral)?,
            &envelope.ephemeral_public,
            &context_digest,
            &quote_digest,
        );
        if let Some(opened) = decrypt(&key, &envelope.nonce, &envelope.ciphertext, &associated)? {
            clear = Some(opened);
            break;
        }
    }
    let Some(clear) = clear else {
        return Ok(None);
    };
    if !clear.starts_with(INNER_DOMAIN) {
        return Err("decrypted winner payload has the wrong domain".into());
    }
    let mut at = INNER_DOMAIN.len();
    let maker_len = usize::from(clear[at]);
    at += 1;
    let recipient = std::str::from_utf8(
        clear
            .get(at..at + maker_len)
            .ok_or_else(|| "decrypted winner payload has an invalid length".to_string())?,
    )
    .map_err(|_| "decrypted winner recipient is not UTF-8")?;
    at += maker_len;
    let payload_len = u32::from_be_bytes(
        clear
            .get(at..at + 4)
            .ok_or_else(|| "decrypted winner payload has an invalid length".to_string())?
            .try_into()
            .expect("four-byte length"),
    ) as usize;
    at += 4;
    let end = at
        .checked_add(payload_len)
        .ok_or_else(|| "decrypted winner payload has an invalid length".to_string())?;
    if end + 64 > clear.len() {
        return Err("decrypted winner payload has an invalid length".into());
    }
    if recipient != maker_id {
        return Err("a key opened an envelope addressed to another maker".into());
    }
    if clear[end..end + 32] != context_digest || clear[end + 32..end + 64] != quote_digest {
        return Err("the encrypted payload and public header disagree".into());
    }
    Ok(Some(clear[at..end].to_vec()))
}
