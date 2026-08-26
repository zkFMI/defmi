//! Zero-knowledge audit of a maker's price policy.
//!
//! The design gives the maker the privacy it was promised: the rule, the
//! inventory and the size limit stay secret. That is worth nothing to the venue
//! unless the hidden policy can still be shown well formed, and worth nothing to
//! the user unless the policy the audit covers is the one the computation
//! evaluated. Three things carry that:
//!
//! - *well-formedness* — every field lies inside a band the venue published,
//!   by Pedersen commitments and range proofs
//! - *binding* — the shares the computing nodes hold open to the committed
//!   values, by Pedersen verifiable secret sharing
//! - *accountability* — the audit is signed under a KYB credential, so a bad
//!   policy is attributable to a legal entity without either becoming public
//!
//! What is deliberately not claimed: these shares are not the shares MP-SPDZ
//! consumes. MP-SPDZ works over its own prime field, so an end-to-end binding
//! needs the computation run over the commitments' field --- which MP-SPDZ
//! accepts as a custom prime, and is the intended route --- or a commit-and-prove
//! link between the two. This establishes the mechanism and its cost, not a
//! deployed guarantee.

use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use qomm_zk::sigma::{prove_bit, verify_bit, BitProof};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

pub const FIELDS: [&str; 6] = ["ask_level", "spread", "slope", "invcoef", "inv", "maxqty"];
const WIDTH_BITS: usize = 32;

/// The bands the venue publishes. A policy is legal when every field is inside
/// its band, which is a statement about the hidden values that the maker proves
/// rather than the venue checks.
#[derive(Clone, Copy, Debug)]
pub struct PolicyBounds {
    pub spread: (i64, i64),
    pub slope: (i64, i64),
    pub invcoef: (i64, i64),
    pub maxqty: (i64, i64),
    pub inv: (i64, i64),
    pub level_band: i64,
}

impl Default for PolicyBounds {
    fn default() -> Self {
        PolicyBounds {
            spread: (2, 400),
            slope: (0, 16),
            invcoef: (0, 8),
            maxqty: (1, 1_000),
            inv: (-4_000, 4_000),
            level_band: 2_000,
        }
    }
}

impl PolicyBounds {
    pub fn for_field(&self, name: &str, ref_mid: i64) -> (i64, i64) {
        match name {
            "ask_level" => (ref_mid - self.level_band, ref_mid + self.level_band),
            "spread" => self.spread,
            "slope" => self.slope,
            "invcoef" => self.invcoef,
            "inv" => self.inv,
            "maxqty" => self.maxqty,
            _ => panic!("no such audited field: {name}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub ask_level: i64,
    pub spread: i64,
    pub slope: i64,
    pub invcoef: i64,
    pub inv: i64,
    pub maxqty: i64,
    pub expiry: i64,
    pub active: bool,
}

impl Policy {
    pub fn field(&self, name: &str) -> i64 {
        match name {
            "ask_level" => self.ask_level,
            "spread" => self.spread,
            "slope" => self.slope,
            "invcoef" => self.invcoef,
            "inv" => self.inv,
            "maxqty" => self.maxqty,
            _ => panic!("no such audited field: {name}"),
        }
    }
}

/// One computing node's share of one field, with its blinding share.
#[derive(Clone, Copy, Debug)]
pub struct PolicyShare {
    pub party: u64,
    pub value_share: Scalar,
    pub blinding_share: Scalar,
}

/// A commitment to a field, plus the VSS ladder that lets any node check its
/// own share against it without help from the dealer.
#[derive(Clone, Debug)]
pub struct FieldCommitment {
    pub commitment: RistrettoPoint,
    pub coefficients: Vec<RistrettoPoint>,
}

pub struct PolicyAudit {
    pub ref_mid: i64,
    pub now_t: i64,
    pub expiry: i64,
    pub fields: Vec<(String, FieldCommitment)>,
    /// One aggregated range proof over all audited fields, and the shifted
    /// commitments it covers.
    pub ranges: RangeProof,
    pub range_commitments: Vec<CompressedRistretto>,
    pub active_proof: BitProof,
    pub active_commitment: RistrettoPoint,
    /// Binds the audit to a KYB credential. Empty when unsigned.
    pub entity_signature: Vec<u8>,
    pub entity_nullifier: RistrettoPoint,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    NotBoundToCurrentState,
    ExpiryOutsideHorizon,
    MissingField(String),
    ShareDoesNotMatchCommitment(String),
    OutOfBand,
    ActiveNotABit,
    NotSignedByCredential,
}

pub struct PolicyCommitter {
    pub key: Pedersen,
    pub bounds: PolicyBounds,
    ranges: RangeCtx,
}

fn scalar(value: i64) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs())
    } else {
        Scalar::from(value as u64)
    }
}

impl Default for PolicyCommitter {
    fn default() -> Self {
        Self::new(PolicyBounds::default())
    }
}

impl PolicyCommitter {
    pub fn new(bounds: PolicyBounds) -> Self {
        PolicyCommitter {
            key: Pedersen::new(b"qomm:policy:v1"),
            bounds,
            ranges: RangeCtx::new(WIDTH_BITS, FIELDS.len().next_power_of_two()),
        }
    }

    /// Pedersen VSS. The ladder of coefficient commitments is public, so a node
    /// checks its own share against it and needs to trust nobody; and the
    /// constant term *is* the field commitment, which is what ties the sharing
    /// to the range proof rather than leaving them two unrelated statements.
    pub fn share<R: RngCore + CryptoRng>(
        &self,
        value: i64,
        blinding: &Scalar,
        n_parties: u64,
        threshold: usize,
        rng: &mut R,
    ) -> (FieldCommitment, Vec<PolicyShare>) {
        let mut value_poly = vec![scalar(value)];
        let mut blind_poly = vec![*blinding];
        for _ in 0..threshold {
            value_poly.push(Scalar::random(rng));
            blind_poly.push(Scalar::random(rng));
        }
        let coefficients: Vec<RistrettoPoint> = value_poly
            .iter()
            .zip(&blind_poly)
            .map(|(v, b)| self.key.commit(v, b))
            .collect();

        let shares = (1..=n_parties)
            .map(|party| {
                let x = Scalar::from(party);
                let mut power = Scalar::ONE;
                let (mut v, mut b) = (Scalar::ZERO, Scalar::ZERO);
                for k in 0..=threshold {
                    v += value_poly[k] * power;
                    b += blind_poly[k] * power;
                    power *= x;
                }
                PolicyShare {
                    party,
                    value_share: v,
                    blinding_share: b,
                }
            })
            .collect();

        (
            FieldCommitment {
                commitment: coefficients[0],
                coefficients,
            },
            shares,
        )
    }

    /// A node accepts its share only if it opens against the public ladder.
    pub fn verify_share(&self, share: &PolicyShare, commitment: &FieldCommitment) -> bool {
        let x = Scalar::from(share.party);
        let mut power = Scalar::ONE;
        let mut expected = RistrettoPoint::default();
        for coefficient in &commitment.coefficients {
            expected += coefficient * power;
            power *= x;
        }
        self.key.commit(&share.value_share, &share.blinding_share) == expected
    }

    #[allow(clippy::type_complexity)]
    #[expect(
        clippy::too_many_arguments,
        reason = "all policy statement fields are explicit to prevent an unaudited default"
    )]
    pub fn audit<R: RngCore + CryptoRng, S: Fn(&[u8]) -> Vec<u8>>(
        &self,
        policy: &Policy,
        ref_mid: i64,
        now_t: i64,
        n_parties: u64,
        threshold: usize,
        entity_nullifier: &RistrettoPoint,
        signer: Option<S>,
        rng: &mut R,
    ) -> Result<(PolicyAudit, Vec<(String, Vec<PolicyShare>)>), &'static str> {
        let context = self.context(ref_mid, now_t, policy.expiry, entity_nullifier);

        let mut fields = Vec::new();
        let mut all_shares = Vec::new();
        // Range proofs are stated on the *offset* value, so a signed field and
        // an unsigned one take the same path.
        let mut offsets = Vec::new();
        let mut blindings = Vec::new();

        for name in FIELDS {
            let (low, high) = self.bounds.for_field(name, ref_mid);
            let value = policy.field(name);
            if value < low || value > high {
                return Err("a policy field is outside its published band");
            }
            let blinding = Scalar::random(rng);
            let (field_commitment, shares) =
                self.share(value, &blinding, n_parties, threshold, rng);
            offsets.push((value - low) as u64);
            blindings.push(blinding);
            fields.push((name.to_string(), field_commitment));
            all_shares.push((name.to_string(), shares));
        }

        let mut t = Self::transcript(&context, "ranges");
        let (ranges, range_commitments) = self.ranges.prove(&mut t, &offsets, &blindings)?;

        let active_blinding = Scalar::random(rng);
        let active_commitment = self
            .key
            .commit(&Scalar::from(u64::from(policy.active)), &active_blinding);
        let active_proof = prove_bit(
            &self.key,
            &mut Self::transcript(&context, "active"),
            &active_commitment,
            policy.active,
            &active_blinding,
            rng,
        );

        let entity_signature = match signer {
            Some(sign) => sign(&self.digest(&fields, &active_commitment, &context)),
            None => Vec::new(),
        };

        Ok((
            PolicyAudit {
                ref_mid,
                now_t,
                expiry: policy.expiry,
                fields,
                ranges,
                range_commitments,
                active_proof,
                active_commitment,
                entity_signature,
                entity_nullifier: *entity_nullifier,
            },
            all_shares,
        ))
    }

    fn transcript(context: &[u8], part: &str) -> Transcript {
        let mut t = Transcript::new(b"qomm:policy:v1");
        t.append_message(b"ctx", context);
        t.append_message(b"part", part.as_bytes());
        t
    }

    fn context(
        &self,
        ref_mid: i64,
        now_t: i64,
        expiry: i64,
        nullifier: &RistrettoPoint,
    ) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"qomm:policy-ctx:");
        for part in [ref_mid, now_t, expiry] {
            h.update(part.to_be_bytes());
        }
        h.update(nullifier.compress().as_bytes());
        h.finalize().to_vec()
    }

    fn digest(
        &self,
        fields: &[(String, FieldCommitment)],
        active: &RistrettoPoint,
        context: &[u8],
    ) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"qomm:policy-digest:");
        h.update(context);
        let mut sorted: Vec<&(String, FieldCommitment)> = fields.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, commitment) in sorted {
            h.update(name.as_bytes());
            for coefficient in &commitment.coefficients {
                h.update(coefficient.compress().as_bytes());
            }
        }
        h.update(active.compress().as_bytes());
        h.finalize().to_vec()
    }
}

/// The venue side: accepts a policy only if the hidden values are legal.
pub struct PolicyAuditor {
    committer: PolicyCommitter,
}

impl Default for PolicyAuditor {
    fn default() -> Self {
        Self::new(PolicyBounds::default())
    }
}

impl PolicyAuditor {
    pub fn new(bounds: PolicyBounds) -> Self {
        PolicyAuditor {
            committer: PolicyCommitter::new(bounds),
        }
    }

    pub fn key(&self) -> &Pedersen {
        &self.committer.key
    }

    pub fn verify<V: Fn(&[u8], &[u8]) -> bool>(
        &self,
        audit: &PolicyAudit,
        now_t: i64,
        ref_mid: i64,
        max_horizon: i64,
        entity_verifier: Option<V>,
    ) -> Result<(), Invalid> {
        if audit.ref_mid != ref_mid || audit.now_t != now_t {
            return Err(Invalid::NotBoundToCurrentState);
        }
        if !(now_t < audit.expiry && audit.expiry <= now_t + max_horizon) {
            return Err(Invalid::ExpiryOutsideHorizon);
        }
        let context = self
            .committer
            .context(ref_mid, now_t, audit.expiry, &audit.entity_nullifier);

        // The range proof must cover the offset of each field's own commitment,
        // in the declared order, and the sharing's constant term must be that
        // same commitment --- otherwise the two statements are about different
        // numbers and neither constrains the other.
        let mut expected = Vec::with_capacity(FIELDS.len());
        for name in FIELDS {
            let entry = audit
                .fields
                .iter()
                .find(|(n, _)| n == name)
                .ok_or_else(|| Invalid::MissingField(name.to_string()))?;
            let field = &entry.1;
            if field.coefficients.first() != Some(&field.commitment) {
                return Err(Invalid::ShareDoesNotMatchCommitment(name.to_string()));
            }
            let (low, _) = self.committer.bounds.for_field(name, ref_mid);
            let shifted = field.commitment - self.committer.key.g * scalar(low);
            expected.push(shifted.compress());
        }
        if audit.range_commitments.len() < expected.len()
            || audit.range_commitments[..expected.len()] != expected[..]
        {
            return Err(Invalid::OutOfBand);
        }
        let mut t = PolicyCommitter::transcript(&context, "ranges");
        if !self
            .committer
            .ranges
            .verify(&mut t, &audit.ranges, &audit.range_commitments)
        {
            return Err(Invalid::OutOfBand);
        }

        if !verify_bit(
            &self.committer.key,
            &mut PolicyCommitter::transcript(&context, "active"),
            &audit.active_commitment,
            &audit.active_proof,
        ) {
            return Err(Invalid::ActiveNotABit);
        }

        if let Some(verify) = entity_verifier {
            let digest = self
                .committer
                .digest(&audit.fields, &audit.active_commitment, &context);
            if !verify(&digest, &audit.entity_signature) {
                return Err(Invalid::NotSignedByCredential);
            }
        }
        Ok(())
    }

    pub fn verify_node_share(&self, share: &PolicyShare, commitment: &FieldCommitment) -> bool {
        self.committer.verify_share(share, commitment)
    }
}

/// Lagrange interpolation at zero, for the reveal path and for tests.
pub fn reconstruct(shares: &[PolicyShare], threshold: usize) -> Scalar {
    let chosen = &shares[..(threshold + 1).min(shares.len())];
    let mut total = Scalar::ZERO;
    for (i, share) in chosen.iter().enumerate() {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (j, other) in chosen.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator *= Scalar::from(other.party);
            denominator *= Scalar::from(other.party) - Scalar::from(share.party);
        }
        total += share.value_share * numerator * denominator.invert();
    }
    total
}
