//! Adaptor signatures: a signature that is finished by a secret, and finishing
//! it hands that secret back.
//!
//! This exists for payment versus payment across two ledgers that share no
//! state. Fair exchange between two parties with no third party is impossible
//! in general, so something has to leak from one side to the other; the only
//! question is what, and to whom. A hash lock leaks a preimage that appears in
//! the clear on both ledgers, which links the two legs for anyone who reads
//! both --- and linking the legs is exactly what the rest of this system spends
//! its cost preventing.
//!
//! An adaptor signature leaks a scalar instead, and only to the party who holds
//! the pre-signature. What lands on either ledger is an ordinary Schnorr
//! signature. A third party reading both ledgers sees two unrelated signatures:
//! there is no shared value to match on, because the nonce points differ by `Y`
//! and `Y` never appears.
//!
//! The construction is the standard one. For a key `X = g^x`, an adaptor point
//! `Y = g^y` and a message `m`:
//!
//! ```text
//! pre-sign   R = g^r,  c = H(R + Y, X, m),  s' = r + c x     -> (R, s')
//! verify     g^{s'} == R + c X
//! adapt      s = s' + y                                      -> (R + Y, s)
//! extract    y = s - s'
//! ```
//!
//! The adapted pair is an ordinary Schnorr signature under nonce point `R + Y`,
//! so a ledger that already verifies Schnorr needs no new code to accept it ---
//! which is the property that makes this usable across a ledger that knows
//! nothing about the swap.
//!
//! What this does *not* do is make the exchange safe on its own. Whoever holds
//! `y` acts first and always has the option not to act, so the party who moves
//! second needs a deadline behind it. That belongs to the protocol, not here;
//! see `qomm-defmi`'s `pvp`.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use crate::sigma::TranscriptExt;

/// A signature that is one scalar short of valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreSignature {
    /// The nonce point *without* the adaptor added.
    pub r: RistrettoPoint,
    pub s: Scalar,
}

/// What the ledger sees: an ordinary Schnorr signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: RistrettoPoint,
    pub s: Scalar,
}

/// The secret a pre-signature is waiting for, and the point that stands for it.
#[derive(Clone, Copy, Debug)]
pub struct Adaptor {
    pub secret: Scalar,
    pub point: RistrettoPoint,
}

impl Adaptor {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Adaptor {
        let secret = Scalar::random(rng);
        Adaptor {
            secret,
            point: &secret * RISTRETTO_BASEPOINT_TABLE,
        }
    }
}

pub fn public_key(secret: &Scalar) -> RistrettoPoint {
    secret * RISTRETTO_BASEPOINT_TABLE
}

/// The challenge. The adaptor point enters through the nonce point and not as a
/// field of its own, which is what leaves the adapted signature ordinary.
fn challenge(nonce_point: &RistrettoPoint, key: &RistrettoPoint, message: &[u8]) -> Scalar {
    let mut t = Transcript::new(b"qomm:zk:adaptor:v1");
    t.append_point(b"R", nonce_point);
    t.append_point(b"X", key);
    t.append_message(b"m", message);
    t.challenge_scalar(b"c")
}

/// Sign in a way that only the holder of the adaptor's secret can finish.
pub fn pre_sign<R: RngCore + CryptoRng>(
    signing_key: &Scalar,
    adaptor_point: &RistrettoPoint,
    message: &[u8],
    rng: &mut R,
) -> PreSignature {
    let r = Scalar::random(rng);
    let nonce = &r * RISTRETTO_BASEPOINT_TABLE;
    let c = challenge(&(nonce + adaptor_point), &public_key(signing_key), message);
    PreSignature {
        r: nonce,
        s: r + c * signing_key,
    }
}

/// Check a pre-signature before relying on it.
///
/// The party who receives one is about to lock money behind it, so it has to be
/// checked before that money moves and not after. This is the check that makes
/// the protocol safe against a counterparty who sends nonsense: without it, the
/// first leg is prepared against a pre-signature that never adapts.
pub fn verify_pre_signature(
    key: &RistrettoPoint,
    adaptor_point: &RistrettoPoint,
    message: &[u8],
    pre: &PreSignature,
) -> bool {
    let c = challenge(&(pre.r + adaptor_point), key, message);
    public_key(&pre.s) == pre.r + c * key
}

/// Finish a pre-signature with the adaptor's secret.
pub fn adapt(pre: &PreSignature, adaptor: &Adaptor) -> Signature {
    Signature {
        r: pre.r + adaptor.point,
        s: pre.s + adaptor.secret,
    }
}

/// Recover the secret from a published signature and the pre-signature it came
/// from. This is the whole mechanism: publishing one leg's signature hands the
/// other leg's key to whoever pre-signed it, and to nobody else.
pub fn extract(pre: &PreSignature, signature: &Signature) -> Scalar {
    signature.s - pre.s
}

/// Ordinary Schnorr verification. A ledger runs this and needs to know nothing
/// about adaptors, pre-signatures or the other ledger.
pub fn verify(key: &RistrettoPoint, message: &[u8], signature: &Signature) -> bool {
    let c = challenge(&signature.r, key, message);
    public_key(&signature.s) == signature.r + c * key
}

/// Sign with no adaptor, for callers that want the same verifier for both.
pub fn sign<R: RngCore + CryptoRng>(
    signing_key: &Scalar,
    message: &[u8],
    rng: &mut R,
) -> Signature {
    let pre = pre_sign(signing_key, &RistrettoPoint::default(), message, rng);
    Signature { r: pre.r, s: pre.s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;
    use rand::rngs::OsRng;

    fn setup() -> (Scalar, RistrettoPoint, Adaptor) {
        let mut rng = OsRng;
        let x = Scalar::random(&mut rng);
        (x, public_key(&x), Adaptor::random(&mut rng))
    }

    #[test]
    fn an_adapted_pre_signature_is_an_ordinary_signature() {
        let (x, key, adaptor) = setup();
        let pre = pre_sign(&x, &adaptor.point, b"leg", &mut OsRng);
        assert!(verify_pre_signature(&key, &adaptor.point, b"leg", &pre));
        assert!(verify(&key, b"leg", &adapt(&pre, &adaptor)));
    }

    #[test]
    fn a_pre_signature_alone_does_not_verify() {
        let (x, key, adaptor) = setup();
        let pre = pre_sign(&x, &adaptor.point, b"leg", &mut OsRng);
        // Read as a finished signature it is simply wrong, which is the point:
        // holding one is not holding the authority to move anything.
        assert!(!verify(&key, b"leg", &Signature { r: pre.r, s: pre.s }));
    }

    #[test]
    fn publishing_the_signature_hands_back_the_secret() {
        let (x, _key, adaptor) = setup();
        let pre = pre_sign(&x, &adaptor.point, b"leg", &mut OsRng);
        assert_eq!(extract(&pre, &adapt(&pre, &adaptor)), adaptor.secret);
    }

    #[test]
    fn the_wrong_secret_does_not_finish_it() {
        let (x, key, adaptor) = setup();
        let other = Adaptor::random(&mut OsRng);
        let pre = pre_sign(&x, &adaptor.point, b"leg", &mut OsRng);
        assert!(!verify(&key, b"leg", &adapt(&pre, &other)));
    }

    #[test]
    fn a_pre_signature_is_bound_to_its_message_and_its_adaptor() {
        let (x, key, adaptor) = setup();
        let pre = pre_sign(&x, &adaptor.point, b"leg", &mut OsRng);
        assert!(!verify_pre_signature(
            &key,
            &adaptor.point,
            b"another leg",
            &pre
        ));
        assert!(!verify_pre_signature(
            &key,
            &Adaptor::random(&mut OsRng).point,
            b"leg",
            &pre
        ));
        assert!(!verify_pre_signature(
            &public_key(&Scalar::random(&mut OsRng)),
            &adaptor.point,
            b"leg",
            &pre
        ));
    }

    #[test]
    fn two_legs_under_one_adaptor_share_nothing_an_observer_can_match() {
        // The property the whole construction is for: a third party holding
        // both published signatures has no value in common to join on.
        let mut rng = OsRng;
        let adaptor = Adaptor::random(&mut rng);
        let (alice, bob) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let a = adapt(
            &pre_sign(&alice, &adaptor.point, b"leg A", &mut rng),
            &adaptor,
        );
        let b = adapt(
            &pre_sign(&bob, &adaptor.point, b"leg B", &mut rng),
            &adaptor,
        );
        assert_ne!(a.r, b.r);
        assert_ne!(a.s, b.s);
        assert_ne!(a.r - b.r, adaptor.point);
        assert_ne!(a.s - b.s, adaptor.secret);
    }

    #[test]
    fn an_ordinary_signature_verifies_the_same_way() {
        let (x, key, _) = setup();
        let sig = sign(&x, b"no swap here", &mut OsRng);
        assert!(verify(&key, b"no swap here", &sig));
        assert_eq!(RistrettoPoint::default(), RistrettoPoint::identity());
    }
}
